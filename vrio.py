"""Objects common to VRIO client and server.
"""
import datetime
import os
import struct
import threading


# File created by user with VRIO server address.
SERVER_ADDR_FNAME = 'serveraddr.txt'

# sbRIO login username. Password is passed to server by cmdline.
SBRIO_USERNAME = 'stefan'         # 'admin'

# Parent folder on sbRIO of binaries.
SBRIO_SCP_DEST = '/home/stefan/'  # '/home/admin/FlightSoftware'

# Maximum runtime of a job in seconds.
SBRIO_JOB_TIMEOUT_S = 60

# Job binary extension.
SBRIO_JOB_BIN_EXT = '.job'

# Filename of job count log.
SERVER_JOB_COUNT_FNAME = 'vrio-job-counts.txt'

# Map of sbRIO IDs to static IPs.
id_to_sbrio = {}
ip_to_sbrio = {}

# Special sbRIO IPs.
SBRIO_IP_ANY = "any"
special_sbrio_ips = [SBRIO_IP_ANY]

# Map of usernames to number of jobs successfully processed.
user_job_counts = {}

# Lock for synchronizing prints by job handling threads.
print_lock = threading.Lock()

# Lock for synchronizing access to job count map.
job_count_lock = threading.Lock()


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
        self._job_lock = threading.Lock()  # Lock for running jobs.
        self._var_lock = threading.Lock()  # Lock for reading/writing members.

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
        w = None
        with self._var_lock:
            w = self._waiters
        return w

    def in_use(self):
        """
        Return
        ------
        bool
            if a job is currently running on the sbRIO
        """
        return self._job_lock.locked()
    
    def acquire(self):
        """Used by a job handling thread to acquire an sbRIO. Blocks until
        the sbRIO is not busy.
        """
        # Increment waiters in thread-safe manner.
        with self._var_lock:
            self._waiters += 1

        # Acquire job lock.
        self._job_lock.acquire()

        # Decrement waiters in thread-safe manner.
        with self._var_lock:
            self._waiters -= 1

    def release(self):
        """Used by a job handing thread to yield control of the sbRIO.
        """
        self._job_lock.release()


def load_sbrio_info():
    """Populates sbRIO ID-IP global maps.
    """
    with open("sbrios.txt", "r") as f:
        idx = 0
        for line in f.readlines():
            ip = line.strip()
            rio = SbRio(idx, ip)
            id_to_sbrio[idx] = rio
            ip_to_sbrio[ip] =  rio
            idx += 1


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
    print_lock.acquire()

    # Get timestamp.
    dt = datetime.datetime.now()

    # Log to stdout.
    line = "[%s // %s] %s" % (str(dt), id, dat)
    print(line)

    # Log to log file.
    with open("vrio-session-%s.txt" % vrio_session_id, 'a') as f:
        f.write(line + '\n')

    print_lock.release()


def count_job(user):
    """Synchronized function for incrementing a user's job count and logging the
    map to disk.

    Parameters
    ----------
    user : str
        username
    """
    job_count_lock.acquire()

    # Increment user's job counter.
    if user not in user_job_counts:
        user_job_counts[user] = 1
    else:
        user_job_counts[user] += 1

    # Save map to disk.
    with open(SERVER_JOB_COUNT_FNAME, 'w') as f:
        for user in user_job_counts:
            f.write(user + ' ' + str(user_job_counts[user]) + '\n')

    job_count_lock.release()


def load_job_counts():
    """Loads the job count map from disk.
    """
    # Creates the file if it doesn't exist.
    open(SERVER_JOB_COUNT_FNAME, 'a').close()

    # Populate map with file contents.
    with open(SERVER_JOB_COUNT_FNAME, 'r') as f:
        for line in f.readlines():
            chunks = line.strip().split(' ')
            user, count = chunks[0], int(chunks[1])
            user_job_counts[user] = count


# Load sbRIO information once module loads.
load_sbrio_info()

# Generate unique session ID. Used for server logging.
vrio_session_id = str(datetime.datetime.now()).replace(' ', '-') \
                                              .replace(':', '-') \
                                              .replace('.', '-')