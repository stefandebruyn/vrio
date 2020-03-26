"""VRIO server that runs on computer to which all sbRIOs are connected. Accepts
job requests from clients, deploys and runs them on the target sbRIO, and
returns the results.

Usage: python3 server.py [SBRIO PASSWORD] [SERVER IP]

Certain inflexible parsing code expects a particular format for the output of
grep and ps, which may vary with Linux flavor. The following scenarios should be
tested before deploying in production:

  #1 Send a generic job to an sbRIO with no contention.

  #2 Send a job that exceeds the runtime limit to an sbRIO with no contention.

  #3 Send a job that runs indefinitely to an sbRIO with no contention.

  #4 Perform 1-3 with an sbRIO that is contended by some other long-running but
     otherwise OK job.

In all cases, the job results--whether successful or timed out--should be
returned to the client with no uncaught errors by the client or server. Job
binaries temporarily saved to the server machine should have been automatically
removed. Job binaries saved to sbRIOs should have been automatically removed,
and timed-out job processes should have been automatically killed.

Other notes:

  - Certain actions by job binaries can defy Paramiko's SSH timeout. Instances
    of this observed so far:
      * Job attempts to manipulate STDIN_FILENO via ioctl().
"""
import os
import paramiko
import scp
import socket
import struct
import sys
import threading
import vrio


# Global job counter used to assign job IDs.
job_counter = 0


class JobHandler(threading.Thread):
    """Handling thread for a client job request.
    """
    def __init__(self, addr, sock, pw):
        """
        Parameters
        ----------
        addr : tuple
            (ip, port) client address returned by socket.connect
        sock : socket.socket
            client socket
        pw : str
            sbRIO password
        """
        threading.Thread.__init__(self)
        self.addr = addr
        self.sock = sock
        self.pw = pw
        # Increment global job counter and assign ID.
        global job_counter
        job_counter += 1
        self.id = "{:04d}".format(job_counter - 1)

    def run_job(self, host, user, pw, job_bin_path):
        """Runs a binary on a remote target and returns the output.

        Parameters
        ----------
        host : str
            hostname
        user : str
            username
        pw : str
            password
        job_bin_path
            fully-qualified path to binary

        Return
        ------
        tuple
            (stdout, stderr) bytes objects
        """
        # Connect to target.
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=pw)

        b_out = bytes()
        b_err = bytes()
        try:
            # Run job.
            stdin, stdout, stderr = ssh.exec_command(
                job_bin_path, timeout=vrio.SBRIO_JOB_TIMEOUT_S)
            b_out = stdout.read()
            b_err = stderr.read()

        except socket.timeout:
            # Job timed out.
            vrio.log(self.id, "Job timed out.")
            b_err = bytes("Job timed out.", 'utf-8')
        
        except Exception as e:
            # Something else went wrong with the job; return exception message.
            vrio.log(self.id, "Error running job: %s" % str(e))
            b_err = bytes(str(e), 'utf-8')

        finally:
            # Kill job process if still running.
            stdin, stdout, stderr = ssh.exec_command(
                "ps -ef | grep %s" % self.id + vrio.SBRIO_JOB_BIN_EXT)
            grep = stdout.read().decode('utf-8')
            pid = None
            for line in grep.split('\n'):
                if self.id in line and "grep" not in line:
                    pid = line.split()[1]  # PID printed in 2nd col.
                    vrio.log(self.id, "Identified job still running with PID %s. Attempting to kill..." % \
                                      pid)
                    break
            if pid is not None:
                ssh.exec_command("kill -9 %s" % pid)
                vrio.log(self.id, "Kill signal sent.")

            # Remove job binary.
            ssh.exec_command('rm ' + job_bin_path)

        # Close connection and conclude.
        ssh.close()
        return b_out, b_err

    def scp_job(self, host, user, pw, port, src, dest):
        """SCPs a job binary to a remote target.

        Parameters
        ----------
        host : str
            hostname
        user : str
            username
        pw : str
            password
        port : int
            port number
        src : str
            source file path
        dest : str
            destination file path
        """
        # SCP file to target.
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.connect(host, username=user, password=pw, look_for_keys=False)
        with scp.SCPClient(ssh.get_transport()) as scpc:
            scpc.put(src, recursive=False, remote_path=dest)
        # Mark file as executable.
        ssh.exec_command('chmod +x ' + dest)
        ssh.close()
    
    def run(self):
        """
        Processes the job in the following steps:
            
            1) Validate the requested sbRIO. If an unknown sbRIO was
               specified, an error message is sent to the client and the
               connection is closed.
            2) Check the status of the requested sbRIO (in use, number of
               waiters) and send this information to the client.
            3) Save the job binary sent in the initial client packet to the
               local disk and wait for the target sbRIO to be available.
            4) SCP the job binary to the target, run the binary through an
               SSH session, and collect the stdout and stderr.
            5) Send stdout + stderr back to the client and close the
               connection.
        """
        # Job binary file name.
        job_bin_fname = self.id + vrio.SBRIO_JOB_BIN_EXT

        try:
            vrio.log(self.id, "Connection from %s. Waiting for sbRIO ID..." %
                     ("%s:%s" % self.addr))
            packet = vrio.recv_payload(self.sock)

            # Unpack target sbRIO ID.
            bid = struct.unpack("I", packet[:4])[0]

            # Validate sbRIO ID.
            if bid not in vrio.id_to_sbrio:
                packet_job_deny = vrio.pack(bytes("Unknown sbRIO requested.",
                                                  'utf-8'))
                self.sock.sendall(packet_job_deny)
                raise vrio.UnknownSbrioError

            # Check requested sbRIO status.
            sbrio = vrio.id_to_sbrio[bid]
            str_use = ("not " if not sbrio.in_use() else "") + "in use"
            str_status = "sbRIO %s is %s and has %s other job(s) queued. Job ID: %s" % \
                         (sbrio.ip(), str_use, sbrio.jobs_waiting(), self.id)
            vrio.log(self.id, "Client is requesting sbRIO at %s; in use: %s, queued: %s" % \
                     (sbrio.ip(), sbrio.in_use(), sbrio.jobs_waiting()))

            # Send client sbRIO status.
            packet_job_ack = vrio.pack(bytes(str_status, 'utf-8'))
            self.sock.sendall(packet_job_ack)

            # Wait for ack packet with username before starting job.
            job_user = vrio.recv_payload(self.sock).decode('utf-8')
            vrio.log(self.id, "Identified user: %s" % job_user)

            # Save job binary.
            job_bin = open(job_bin_fname, "wb")
            job_bin.write(packet[4:])
            job_bin_qpath = job_bin.name
            job_bin.close()

            # Run job.
            vrio.log(self.id, "Acquiring sbRIO...")
            sbrio.acquire()
            
            try:
                vrio.log(self.id, "sbRIO acquired. Copying job to sbRIO...")

                # SCP job binary to target rio.
                sbrio_job_qpath = os.path.join(vrio.SBRIO_SCP_DEST,
                                               job_bin_fname)
                self. scp_job(sbrio.ip(), vrio.SBRIO_USERNAME, self.pw, 20,
                              job_bin_qpath, sbrio_job_qpath)
                vrio.log(self.id, "Job copied. Running...")

            except TimeoutError as e:
                # Target sbRIO was unreachable.
                sbrio.release()
                packet_err = vrio.pack(bytes("Requested sbRIO was unreachable. Is it plugged in?",
                                             'utf-8'))
                self.sock.sendall(packet_err)
                raise vrio.JobScpError(str(e))
            
            except Exception as e:
                # Something else went wrong; release sbRIO and end connection.
                sbrio.release()
                packet_err = vrio.pack(bytes("An error occurred while SCPing the job binary.",
                                             'utf-8'))
                self.sock.sendall(packet_err)
                raise vrio.JobScpError(str(e))

            try:
                # Run job and capture output.
                b_out, b_err = self.run_job(sbrio.ip(), vrio.SBRIO_USERNAME,
                                            self.pw, sbrio_job_qpath)
            except Exception as e:
                # Something went wrong; release sbRIO and end connection.
                sbrio.release()
                packet_err = vrio.pack(bytes("An error occurred while running the job.",
                                             'utf-8'))
                self.sock.sendall(packet_err)
                raise vrio.JobRunError(str(e))

            sbrio.release()
            vrio.log(self.id, "Job done, sbRIO released.")
            vrio.count_job(job_user)

            # Return results to client.
            packet_results = vrio.pack(b_out + b_err)
            self.sock.sendall(packet_results)
            vrio.log(self.id, "Job results sent to client.")

        except vrio.UnknownSbrioError:
            # Client requested an unknown sbRIO.
            vrio.log(self.id, "Client sent an invalid sbRIO ID. Aborting...")

        except vrio.JobScpError as e:
            # Error occurred while SCPing job binary to target.
            vrio.log(self.id, "Failed to SCP job binary: %s" % str(e))

        except vrio.JobRunError as e:
            # Error occurred while running job binary on target.
            vrio.log(self.id, "Failed to run job binary: %s" % str(e))

        except Exception as e:
            # Something else went wrong.
            vrio.log(self.id, "Failed to process job: %s" % str(e))
            packet_err = vrio.pack(bytes("Failed to process job. Go yell at Stefan.",
                                         'utf-8'))
            self.sock.sendall(packet_err)

        finally:
            # Clean up local job binary if one was saved.
            try:
                if os.path.exists(job_bin_fname):
                    os.remove(job_bin_fname)
            except Exception:
                vrio.log(self.id, "WARNING: Failed to delete job binary %s" \
                         % job_bin_name)

            # Close connection.
            self.sock.close()
            vrio.log(self.id, "Connection closed.")


if __name__ == "__main__":
    # Get sbRIO password from cmdline.
    if len(sys.argv) != 3:
        print("Usage: python3 server.py [SBRIO PASSWORD] [SERVER IP]")
        exit()
    sbrio_password = sys.argv[1]

    # Parse server IP.
    chunks = sys.argv[2].split(':')
    server_addr = chunks[0], int(chunks[1])

    # Load job counts.
    vrio.load_job_counts()

    vrio.printctr("[VERY REMOTE IO]", ' ')
    vrio.printctr("Science spites mother nature once again.", ' ')

    # Create, bind, and listen on server socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(server_addr)
    sock.listen(1)
    vrio.log("main", "Opened server on %s:%s. Listening..." % server_addr)

    # Wait for client connections.
    while True:
        # Dispatch handler thread to service request.
        conn, client_addr = sock.accept()
        conn.settimeout(60)
        handler = JobHandler(client_addr, conn, sbrio_password)
        handler.start()
