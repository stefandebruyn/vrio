"""VRIO server that runs on computer to which all sbRIOs are connected. Accepts
job requests from clients, deploys and runs them on the target sbRIO, and
returns the results.

Usage: python3 server.py [SBRIO PASSWORD] [SERVER IP]

Certain inflexible parsing code expects a particular format for the output of
grep and ps, which may vary with Linux flavor. The following scenarios should be
tested before deploying in production:

  #1 Send a generic job to an sbRIO with no contention.

  #2 Send a job that exceeds the runtime limit to an sbRIO with no contention.

  #3 Perform 1 and 2 with an sbRIO that is contended by some other long-running
     but otherwise OK job.

In all cases, the job results--whether successful or timed out--should be
returned to the client with no uncaught errors by the client or server. Job
binaries temporarily saved to the server machine should have been automatically
removed. Job binaries saved to sbRIOs should have been automatically removed,
and timed-out job processes should have been automatically killed.

Other notes:

  - Certain actions by job binaries can defy Paramiko's SSH timeout. Instances
    of this observed so far:
      * Job attempts to manipulate STDIN_FILENO via ioctl().
  - Paramiko appears to capture the stdout and stderr of the program executed
    over SSH rather than the shell itself. Consequently, segfaults will not
    appear in the returned output. Passing get_pty=True to exec_command to
    request a pseudo-terminal from the remote target seems like it would fix
    this, but it doesn't.
"""
from Crypto.Cipher import AES
import hashlib
import os
import paramiko
import scp
import socket
import struct
import subprocess
import sys
import threading
import vrio


# Global job counter used to assign job IDs.
job_counter = 0

# Lock for synchronizing edits to global job counter.
job_counter_lock = threading.Lock()

# Global list of online sbRIOs, updated periodically by SbrioPingThread.
online_sbrios = []

# Lock for synchronizing access to online sbRIO list.
online_sbrios_lock = threading.Lock()

# Whether or not to allow jobs run on "any" sbRIO. This requires the ping thread
# be periodically pinging all sbRIOs, which may be unattractive for reasons of
# scheduling determinism (on the sbRIOs--have to keep servicing ping requests).
allow_any_sbrio = False

# Key and VI for decrypting incoming binaries. Read from disk at entry.
aes_key = None
aes_vi = None


class SbrioPingThread(threading.Thread):
    """Thread that periodically updates the global list of online sbRIOs.
    """
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        """Updates the global list of online sbRIOs as fast as possible. Most of
        the time is spent pinging. Each ping has a 1 second timeout, so in the
        worst case, the list is updated ever n seconds, where n is the number of
        sbRIOs.
        """
        global online_sbrios, online_sbrios_lock
        while True:
            ping = ping_sbrios()
            online_sbrios_lock.acquire()
            online_sbrios = ping
            online_sbrios_lock.release()


class JobHandlerThread(threading.Thread):
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
        global job_counter, job_counter_lock
        c = None
        with job_counter_lock:
            job_counter += 1
            c = job_counter
        self.id = "{:04d}".format(c - 1)

    def run_job(self, host, user, pw, job_bin_path, cmdline_args):
        """Runs a binary on a remote target and returns the output.

        Parameters
        ----------
        host : str
            hostname
        user : str
            username
        pw : str
            password
        job_bin_path : str
            fully-qualified path to binary
        cmdline_args : list
            list of str cmdline args for binary

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
            cmd = job_bin_path + ' ' + ' '.join(cmdline_args)
            stdin, stdout, stderr = ssh.exec_command(
                cmd, timeout=vrio.SBRIO_JOB_TIMEOUT_S)
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

            # Verify magic number integrity.
            global aes_key, aes_vi
            hasher = hashlib.sha512()
            hasher.update(aes_key + aes_iv)
            b_magic = hasher.digest()
            b_magic_recv = packet[:64]
            if b_magic != b_magic_recv:
                packet_job_deny = vrio.pack(bytes("Magic number mismatch.",
                                                  'utf-8'))
                self.sock.sendall(packet_job_deny)
                raise vrio.BadMagicError
            # Slice packet b/c I'm too lazy to update indices.
            packet = packet[64:]

            # Unpack target sbRIO ID.
            bid = struct.unpack("I", packet[:4])[0]

            # Validate sbRIO ID.
            if bid not in vrio.id_to_sbrio:
                packet_job_deny = vrio.pack(bytes("Unknown sbRIO requested.",
                                                  'utf-8'))
                self.sock.sendall(packet_job_deny)
                raise vrio.UnknownSbrioError

            # Look up the requested sbRIO resource.
            sbrio = vrio.id_to_sbrio[bid]
            if sbrio.ip() == vrio.SBRIO_IP_ANY:
                # Client asked for any sbRIO. Verify this is allowed.
                if not allow_any_sbrio:
                    packet_err = vrio.pack(
                        bytes("\"Any\" requests are currently disabled. Send a specific IP!",
                              'utf-8'))
                    self.sock.sendall(packet_err)
                    raise vrio.AnySbrioDisallowedError()
                # Looks OK.
                vrio.log(self.id, "Client asked for any sbRIO. Pinging online sbRIOs...")
                global online_sbrios, online_sbrios_lock
                online_sbrios_lock.acquire()
                sbrio_opts = online_sbrios
                online_sbrios_lock.release()
                # If none are available, report that.
                if len(sbrio_opts) == 0:
                    packet_err = vrio.pack(
                        bytes("No sbRIOs are currently online.", 'utf-8'))
                    self.sock.sendall(packet_err)
                    raise vrio.NoSbriosAvailableError()
                # Identify least load, where load = jobs queued + in use.
                best_sbrio = None
                best_sbrio_load = -1
                for sb in sbrio_opts:
                    load = sb.jobs_waiting() + sb.in_use()
                    if best_sbrio is None or load < best_sbrio_load:
                        best_sbrio = sb
                        best_sbrio_load = load
                # Reassign target sbRIO.
                sbrio = best_sbrio

            # Check target sbRIO status.
            str_use = ("not " if not sbrio.in_use() else "") + "in use"
            str_status = "sbRIO %s is %s and has %s other job(s) queued. Job ID: %s" % \
                         (sbrio.ip(), str_use, sbrio.jobs_waiting(), self.id)
            vrio.log(self.id, "Job is targeting sbRIO at %s; in use: %s, queued: %s" % \
                     (sbrio.ip(), sbrio.in_use(), sbrio.jobs_waiting()))

            # Send client sbRIO status.
            packet_job_ack = vrio.pack(bytes(str_status, 'utf-8'))
            self.sock.sendall(packet_job_ack)

            # Wait for ack packet with username and cmdline args before starting
            # job.
            packet_goahead = vrio.recv_payload(self.sock)
            subpacket_user_size = struct.unpack("I", packet_goahead[:4])[0]
            subpacket_user = packet_goahead[4:4+subpacket_user_size]
            subpacket_cmdline_size = struct.unpack(
                "I", packet_goahead[4+subpacket_user_size:
                                    8+subpacket_user_size])[0]
            subpacket_cmdline = packet_goahead[8+subpacket_user_size:
                                               8+subpacket_user_size + \
                                               subpacket_cmdline_size]
            job_user = subpacket_user.decode('utf-8')
            cmdline_args = subpacket_cmdline.decode('utf-8').split(',')

            vrio.log(self.id, "Identified user: %s" % job_user)
            vrio.log(self.id, "Parsed cmdline args: [%s]" % \
                              ', '.join(cmdline_args))

            # Decrypt job binary.
            vrio.log(self.id, "Decrypting job binary...")
            b_job_enc = packet[4:]
            aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
            b_job = aes.decrypt(b_job_enc)
            vrio.log(self.id, "Finished decrypting job binary.")

            # Save decrypted job binary to disk for later SCP.
            job_bin = open(job_bin_fname, "wb")
            job_bin.write(b_job)
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
                                            self.pw, sbrio_job_qpath,
                                            cmdline_args)
            except Exception as e:
                # Something went wrong; release sbRIO and end connection.
                sbrio.release()
                packet_err = vrio.pack(bytes("An error occurred while running the job.",
                                             'utf-8'))
                self.sock.sendall(packet_err)
                raise vrio.JobRunError(str(e))

            # Job done, either ran ok or timed out. Release sbRIO.
            sbrio.release()
            vrio.log(self.id, "Job done, sbRIO released.")
            vrio.count_job(job_user)

            # Return results to client.
            packet_results = vrio.pack(b_out + b_err)
            self.sock.sendall(packet_results)
            vrio.log(self.id, "Job results sent to client.")

        except vrio.BadMagicError:
            # Client job request packet had wrong magic number.
            vrio.log(self.id, "Client sent wrong magic number. Aborting...")

        except vrio.UnknownSbrioError:
            # Client requested an unknown sbRIO.
            vrio.log(self.id, "Client sent an invalid sbRIO ID. Aborting...")

        except vrio.NoSbriosAvailableError:
            # Client asked for "any" sbRIO, but none were online.
            vrio.log(self.id, "No sbRIOs are online. Aborting...")

        except vrio.AnySbrioDisallowedError:
            # Client asked for "any" sbRIO but that's not allowed.
            vrio.log(self.id, "Request for \"any\" sbRIO rejected.")

        except vrio.JobScpError as e:
            # Error occurred while SCPing job binary to target.
            vrio.log(self.id, "Failed to SCP job binary: %s" % str(e))

        except vrio.JobRunError as e:
            # Error occurred while running job binary on target.
            vrio.log(self.id, "Failed to run job binary: %s" % str(e))

        except Exception as e:
            try:
                # Something else went wrong.
                vrio.log(self.id, "Failed to process job: %s" % str(e))
                packet_err = vrio.pack(bytes("Failed to process job. Go yell at Stefan.",
                                            'utf-8'))
                self.sock.sendall(packet_err)
            except Exception:
                vrio.log(self.id, "Failed to respond to client.")

        # Clean up local job binary if one was saved.
        try:
            if os.path.exists(job_bin_fname):
                os.remove(job_bin_fname)
        except Exception:
            vrio.log(self.id, "WARNING: Failed to delete job binary %s" \
                        % job_bin_name)

        # Close connection.
        try:
            self.sock.close()
            vrio.log(self.id, "Connection closed.")
        except Exception:
            vrio.log(self.id, "Failed to close socket.")


def ping_sbrios():
    """Gets a list of all online sbRIOs by pinging each in sequence.

    Return
    ------
    list
        list of online vrio.Sbrios
    """
    online = []
    for rio in vrio.id_to_sbrio.values():
        if rio.ip() in vrio.special_sbrio_ips: continue
        output = subprocess.run(("ping -c 1 -W 1 %s" % rio.ip()).split(' '),
                                stdout=subprocess.PIPE).stdout.decode('utf-8')
        if "100% packet loss" not in output:
            online.append(rio)
    return online


if __name__ == "__main__":
    # Validate usage.
    if len(sys.argv) != 3:
        print("Usage: python3 server.py [SBRIO PASSWORD] [SERVER IP]")
        exit()

    # Read encryption key from file.
    with open(vrio.KEY_FNAME, 'rb') as f:
        full = f.read().strip()
        assert len(full) == 32
        aes_key = full[:16]
        aes_iv = full[16:] 

    # Parse cmdline arguments.
    sbrio_password = sys.argv[1]
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

    if allow_any_sbrio:
        # Start sbRIO ping thread.
        ping_thread = SbrioPingThread()
        ping_thread.start()
        vrio.log("main", "Started sbRIO ping thread.")

    # Wait for client connections.
    while True:
        # Dispatch handler thread to service request.
        conn, client_addr = sock.accept()
        conn.settimeout(60)
        handler = JobHandlerThread(client_addr, conn, sbrio_password)
        handler.start()
