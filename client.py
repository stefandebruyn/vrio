"""VRIO client that runs on the AvSw developer's machine. A compiled binary and
sbRIO IP are sent to the VRIO server, which deploys the binary to the requested
sbRIO and returns the results.

Usage: python3 client.py [SBRIO IP] [PATH TO BINARY]
"""
import os
import socket
import struct
import sys
import vrio


if __name__ == "__main__":
    # Validate usage.
    if len(sys.argv) != 3:
        print("Usage: python3 client.py [SBRIO IP] [PATH TO BINARY]")
        exit()

    # Get server address from file.
    if not os.path.exists(vrio.SERVER_ADDR_FNAME):
        print("Could not find server address file")
        exit()
    server_addr = None
    with open(vrio.SERVER_ADDR_FNAME, "r") as f:
        chunks = f.readlines()[0].strip().split(':')
        server_addr = chunks[0], int(chunks[1])

    # Validate requested sbRIO.
    if sys.argv[1] not in vrio.ip_to_sbrio:
        print("Unknown sbRIO %s" % sys.argv[1] + ". Known IPs:")
        for ip in vrio.ip_to_sbrio.keys():
            print(ip)
        exit()
    sbrio_id = vrio.ip_to_sbrio[sys.argv[1]].id()
    job_binary_path = sys.argv[2]

    # Validate requested file.
    if not os.path.exists(job_binary_path):
        print("Could not find file: %s" % job_binary_path)
        exit()

    print("Targeting sbRIO %s with file %s" % (sys.argv[1], job_binary_path))

    # Attempt connection to server.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to VRIO server at %s:%s..." % server_addr)
    sock.connect(server_addr)

    try:
        # Build and send job request packet.
        print("Connected to server. Building job request...")
        b_bid = struct.pack("I", sbrio_id)
        b_job = open(job_binary_path, "rb").read()
        packet_req = vrio.pack(b_bid + b_job)
        print("Done. Sending job request...")
        sock.sendall(packet_req)

        # Receive status on requested sbRIO from server.
        packet_status = vrio.recv_payload(sock)
        status_plaintext = packet_status.decode('utf-8')

        if "job(s) queued" not in status_plaintext:  # Lazy rejection checking.
            print(status_plaintext)
            raise vrio.JobRejectedError()
        
        # Acknowledge receipt of sbRIO status and wait for job results. This
        # packet contains the client's local username for logging purposes.
        sock.sendall(vrio.pack(bytes(os.getlogin(), 'utf-8')))
        print(status_plaintext + ". Waiting for results...")
        packet_results = vrio.recv_payload(sock)

        # Decode results and conclude.
        vrio.printctr(" BEGIN JOB RESULTS ", '-')
        print(packet_results.decode('utf-8'))
        vrio.printctr(" END JOB RESULTS ", '-')

    except vrio.JobRejectedError:
        # Move on; error already printed.
        pass

    finally:
        # Close connection.
        sock.close()