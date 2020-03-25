"""Objects common to VRIO client and server.
"""
import datetime
import os
import struct
import threading


# VRIO server address.
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
SERVER_ADDR = (SERVER_IP, SERVER_PORT)

# sbRIO login username. Password is passed to server by cmdline.
SBRIO_USERNAME = 'stefan'         # 'admin'

# Parent folder on sbRIO of binaries.
SBRIO_SCP_DEST = '/home/stefan/'  # '/home/admin/FlightSoftware'

# Maximum runtime of a job in seconds.
SBRIO_JOB_TIMEOUT_S = 60

# Job binary extension.
SBRIO_JOB_BIN_EXT = '.job'

# Map of sbRIO IDs to static IPs.
id_to_sbrio = {}
ip_to_sbrio = {}

# Lock for synchronizing prints by job handling threads.
print_lock = threading.Lock()


class UnknownSbrioError(Exception):
    """Used by server to handle unknown sbRIO ID sent by client.
    """
    pass


class JobRejectedError(Exception):
    """Used by client to handle unhappy response from server.
    """
    pass


class JobTimeoutError(Exception):
    """Used by server to handle job timeouts.
    """
    pass


class JobScpError(Exception):
    """Used by server to handle errors when SCPing job binary to target sbRIO.
    Pass generated exception message into constructor.
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class JobRunError(Exception):
    """Used by server to handle errors when running the job binary on target
    sbRIO. Pass generated exception message into constructor.
    """
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class SbRio():
    """Resource object for a single sbRIO.
    """
    def __init__(self, id, ip):
        """
        Parameters
        ----------
        id : int
            sbRIO ID
        ip : str
            sbRIO IP
        """
        self._id = id
        self._ip = ip
        self._waiters = 0
        self._lock = threading.Lock()

    def id(self):
        """
        Return
        ------
        int
            sbRIO ID
        """
        return self._id

    def ip(self):
        """
        Return
        ------
        str
            sbRIO IP
        """
        return self._ip

    def jobs_waiting(self):
        """
        Return
        ------
        int
            number of jobs waiting to run on sbRIO
        """
        return self._waiters

    def in_use(self):
        """
        Return
        ------
        bool
            if a job is currently running on the sbRIO
        """
        return self._lock.locked()
    
    def acquire(self):
        """Used by a job handling thread to acquire an sbRIO. Blocks until
        the sbRIO is not busy.
        """
        self._waiters += 1
        self._lock.acquire()
        self._waiters -= 1

    def release(self):
        """Used by a job handing thread to yield control of the sbRIO.
        """
        self._lock.release()


def load_sbrio_info():
    """Populates sbRIO ID-IP global maps.
    """
    with open("sbrios.txt", "r") as f:
        for line in f.readlines():
            pair = [val.strip() for val in line.split(",")]
            bid, ip = int(pair[0]), pair[1]
            rio = SbRio(bid, ip)
            id_to_sbrio[bid] = rio
            ip_to_sbrio[ip] =  rio


def pack(data):
    """Packages binary data into a packet with a leading payload size.

    Parameters
    ----------
    data : bytes
        binary data

    Return
    ------
    bytes
        packet with leading uint32_t payload size
    """
    data_size = len(data)
    b_size = struct.pack("I", data_size)
    return b_size + data


def recv_payload(sock):
    """Receives a complete packet from a socket.

    Parameters
    ----------
    sock : socket.socket
        recv socket
    
    Return
    ------
    bytes
        packet payload (with leading metadata removed)
    """
    packet = bytes()

    # RX the leading uint32_t payload size.
    while len(packet) < 4:
        packet += sock.recv(4)

    # Unpack payload size.
    payload_size_bytes = struct.unpack("I", packet[:4])[0]

    # Continue RXing until receipt of entire payload.
    while len(packet) - 4 < payload_size_bytes:
        packet += sock.recv(16)

    # RX complete. Return payload only.
    return packet[4:]


def printctr(str, pad=' '):
    """Prints a string centered in the terminal. Synchronized with print lock.

    Parameters
    ----------
    str : str
        string to print
    pad : str
        character to pad left and right of centered string with
    """
    rows, cols = os.popen('stty size', 'r').read().split()
    rows = int(rows)
    cols = int(cols)

    print_lock.acquire()

    if len(str) > cols:
        print(str)
        print_lock.release()
        return

    padding = (cols - len(str)) // 2
    p = len(str)
    for i in range(padding):
        print(pad, end='')
        p += 1
    print(str, end='')
    while p < cols:
        print(pad, end='')
        p += 1
    print("")

    print_lock.release()


def log(id, dat):
    """Timestamped logging utility used by job handling threads. Synchronized
    with print lock.

    Parameters
    ----------
    id : str
        unique identifier
    dat : str
        string to log
    """
    dt = datetime.datetime.now()
    print_lock.acquire()
    print("[%s // %s] %s" % (str(dt), id, dat))
    print_lock.release()


# Load sbRIO information once module loads.
load_sbrio_info()