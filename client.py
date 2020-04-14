"""VRIO client that runs on the AvSw developer's machine. A compiled binary and
sbRIO IP are sent to the VRIO server, which deploys the binary to the requested
sbRIO and returns the results.

Requires a "serveraddr.txt" file in the same directory containing the ip:port
server address.

Usage: python3 client.py [SBRIO IP] [PATH TO BINARY] [BINARY ARGS]

A value of "any" for sbRIO IP will target the sbRIO that is least contended.
This may be disabled server-side to limit interrupts to sbRIOs.
"""
from Crypto.Cipher import AES
import hashlib
import os
import socket
import struct
import sys
import vrio


if __name__ == "__main__":
    # Validate usage.
    if len(sys.argv) < 4:
        print("Usage: python3 client.py [SBRIO IP] [PATH TO BINARY] [BINARY ARGS]")
        exit()

    # Get server address from file.
    if not os.path.exists(vrio.SERVER_ADDR_FNAME):
        print("Could not find server address file")
        exit()
    server_addr = None
    with open(vrio.SERVER_ADDR_FNAME, "r") as f:
        chunks = f.readlines()[0].strip().split(':')
        server_addr = chunks[0], int(chunks[1])

    # Get encryption key from file.
    if not os.path.exists(vrio.KEY_FNAME):
        print("Could not find key file")
        exit()
    key, iv = None, None
    with open(vrio.KEY_FNAME, 'rb') as f:
        full = f.read().strip()
        if len(full) != 32:
            print("Key was of incorrect length %s bytes" % len(full))
            exit()
        key = full[:16]
        iv = full[16:] 

    # Validate requested sbRIO.
    if sys.argv[1] not in vrio.ip_to_sbrio:
        print("Unknown sbRIO %s" % sys.argv[1] + ". Valid arguments:")
        for ip in sorted(vrio.ip_to_sbrio.keys()):
            print(ip)
        exit()
    sbrio_id = vrio.ip_to_sbrio[sys.argv[1]].id()
    job_binary_path = sys.argv[2]

    # Validate requested file.
    if not os.path.exists(job_binary_path):
        print("Could not find file: %s" % job_binary_path)
        exit()

    sbrio_str = "%s sbRIO" if sys.argv[1] == vrio.SBRIO_IP_ANY else \
                "sbRIO %s"
    print(("Targeting " + sbrio_str + " with file %s") % \
          (sys.argv[1], job_binary_path))

    # Attempt connection to server.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to VRIO server at %s:%s..." % server_addr)
    sock.connect(server_addr)
    print("Connected to server. Building job request...")

    try:
        # Encrypt job binary.
        aes = AES.new(key, AES.MODE_CBC, iv)
        b_job = open(job_binary_path, "rb").read()
        b_job_enc = aes.encrypt(b_job)

        # Hash encryption key to be used as magic authentication number.
        hasher = hashlib.sha512()
        hasher.update(key + iv)
        b_magic = hasher.digest()

        # Build and send job request packet.
        b_bid = struct.pack("I", sbrio_id)
        packet_req = vrio.pack(b_magic + b_bid + b_job_enc)
        print("Done. Sending job request...")
        sock.sendall(packet_req)

        # Receive status on requested sbRIO from server.
        packet_status = vrio.recv_payload(sock)
        status_plaintext = packet_status.decode('utf-8')

        if "job(s) queued" not in status_plaintext:  # Lazy rejection checking.
            print("Job rejected by server: " + status_plaintext)
            raise vrio.JobRejectedError()
        
        # Acknowledge receipt of sbRIO status and wait for job results. This
        # packet contains the client's local username (for logging) and cmdline
        # args for the binary.
        subpacket_user = vrio.pack(bytes(os.getlogin(), 'utf-8'))
        cmdline_args = ','.join(sys.argv[3:])
        subpacket_cmdline = vrio.pack(bytes(cmdline_args, 'utf-8'))
        packet_ack = vrio.pack(subpacket_user + subpacket_cmdline)
        sock.sendall(packet_ack)
        print(status_plaintext + ". Waiting for results...")
        packet_results = vrio.recv_payload(sock)

        # Decode results and conclude.
        vrio.printctr(" BEGIN JOB RESULTS ", '-')
        print(packet_results.decode('utf-8'))
        vrio.printctr(" END JOB RESULTS ", '-')

    except vrio.JobRejectedError:
        # Move on; error already printed.
        pass

    except Exception as e:
        # Something else went wrong.
        print(str(e))

    # Close connection.
    sock.close()