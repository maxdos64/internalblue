#!/usr/bin/env python2

from __future__ import absolute_import

import socket
import struct

from future import standard_library

standard_library.install_aliases()
from builtins import str
from builtins import zip
from builtins import range
import datetime
from internalblue.utils.pwnlib_wrapper import log, context, p32, u16, p16, u32
import fcntl
from .core import InternalBlue
from . import hci
import queue as queue2k
import threading


class Injector():
    """ We need this helper to wrap writes to the s_inject socket in the remaining internalblue to a proper write with header (as BTStack Daemon expects it) """

    def __init__(self, socket):
        self.socket = socket

    def send(self, msg):
        """ Call it with msg being a valid HCI message to talk to BTstack Daemon """
        packet_type = msg[0]
        msg = msg[1:]
        channel = 0
        length = len(msg)
        header = struct.pack("<HHH", packet_type, channel, length)
        self.socket.sendall(header + msg)

    def close(self):
        self.socket.close()

class BTstackCore(InternalBlue):
    """ Manages interaction with a BTstack Daemon """
    def __init__(
        self,
        queue_size=1000,
        btsnooplog_filename="btsnoop.log",
        log_level="info",
        fix_binutils="True",
        data_directory=".",
        replay=False,
    ):
        super(BTstackCore, self).__init__(
            queue_size,
            btsnooplog_filename,
            log_level,
            fix_binutils,
            data_directory,
            replay,
        )
        self.btsnooplog_file_lock = threading.Lock()
        self.serial = False
        self.doublecheck = False

    def local_connect(self):
        """
        """
        if not self.host:
            log.warn("No BTstack daemon host defined")
            return False

        if not self.port:
            log.warn("No BTstack daemon port defined")
            return False

        if not self._setupSockets():
            log.critical("BTstack socket could not be established!")
            return False

        return True

    def _btsnoop_pack_time(self, time):
        """
        Takes datetime object and returns microseconds since 2000-01-01.

        see https://github.com/joekickass/python-btsnoop

        Record time is a 64-bit signed integer representing the time of packet arrival,
        in microseconds since midnight, January 1st, 0 AD nominal Gregorian.

        In order to avoid leap-day ambiguity in calculations, note that an equivalent
        epoch may be used of midnight, January 1st 2000 AD, which is represented in
        this field as 0x00E03AB44A676000.
        """
        time_betw_0_and_2000_ad = int("0x00E03AB44A676000", 16)
        time_since_2000_epoch = time - datetime.datetime(2000, 1, 1)
        packed_time = time_since_2000_epoch + datetime.timedelta(
            microseconds=time_betw_0_and_2000_ad
        )
        return int(packed_time.total_seconds() * 1000 * 1000)

    def device_list(self):
        # type: () -> List[DeviceTuple]
        pass

    def _recvThreadFunc(self):
        """
        This is the run-function of the recvThread. It receives HCI events from the
        s_snoop socket. The HCI packets are encapsulated in btsnoop records (see RFC 1761).
        Received HCI packets are being put into the queues inside registeredHciRecvQueues and
        passed to the callback functions inside registeredHciCallbacks.
        The thread stops when exit_requested is set to True. It will do that on its own
        if it encounters a fatal error or the stackDumpReceiver reports that the chip crashed.
        """

        log.debug("Receive Thread started.")

        while not self.exit_requested:
            # Little bit ugly: need to re-apply changes to the global context to the thread-copy
            context.log_level = self.log_level

            # Read the record data
            try:
                header = self.s_snoop.recv(6)
                (packet_type, channel, length) = struct.unpack("<HHH", header)
                record_data = self.s_snoop.recv(length)
                record_data = bytearray(record_data)
                # Repackage so the rest of internalblue can handle the packet (packet type followed by payload)
                record_data = packet_type.to_bytes(1, 'little') + record_data
            except socket.timeout:
                continue  # this is ok. just try again without error
            except Exception as e:
                log.critical(
                    "Lost device interface with exception {}, terminating receive thread...".format(
                        e
                    )
                )
                self.exit_requested = True
                continue

            # btsnoop record header data:
            btsnoop_orig_len = len(record_data)
            btsnoop_inc_len = len(record_data)
            btsnoop_flags = 0
            btsnoop_drops = 0
            btsnoop_time = datetime.datetime.now()

            if btsnoop_orig_len == 0:
                continue

            # Put all relevant infos into a tuple. The HCI packet is parsed with the help of hci.py.
            record = (
                hci.parse_hci_packet(record_data),
                btsnoop_orig_len,
                btsnoop_inc_len,
                btsnoop_flags,
                btsnoop_drops,
                btsnoop_time,
            )

            log.debug(
                "_recvThreadFunc Recv: [" + str(btsnoop_time) + "] " + str(record[0])
            )

            # Write to btsnoop file:
            if self.write_btsnooplog:
                btsnoop_record_hdr = struct.pack(
                    ">IIIIq",
                    btsnoop_orig_len,
                    btsnoop_inc_len,
                    btsnoop_flags,
                    btsnoop_drops,
                    self._btsnoop_pack_time(btsnoop_time),
                )
                with self.btsnooplog_file_lock:
                    self.btsnooplog_file.write(btsnoop_record_hdr)
                    self.btsnooplog_file.write(record_data)
                    self.btsnooplog_file.flush()

            # Put the record into all queues of registeredHciRecvQueues if their
            # filter function matches.
            for queue, filter_function in self.registeredHciRecvQueues:
                if filter_function is None or filter_function(record):
                    try:
                        queue.put(record, block=False)
                    except queue2k.Full:
                        log.warn(
                            "recvThreadFunc: A recv queue is full. dropping packets.."
                        )

            # Call all callback functions inside registeredHciCallbacks and pass the
            # record as argument.
            for callback in self.registeredHciCallbacks:
                callback(record)

            # Check if the stackDumpReceiver has noticed that the chip crashed.
            # if self.stackDumpReceiver.stack_dump_has_happend:
            # A stack dump has happend!
            # log.warn("recvThreadFunc: The controller send a stack dump.")
            # self.exit_requested = True

        log.debug("Receive Thread terminated.")

    def configure_sockets(self, host, port):
        self.host = host
        self.port = port
        self.interface = 1

    def _setupSockets(self):

        self.s_snoop = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s_snoop.settimeout(2)
        self.s_snoop.connect((self.host, self.port))

        log.debug("_setupSockets: Bound socket.")

        # same socket for input and output (this is different from adb here!)
        self.s_inject = Injector(self.s_snoop)

        # Write Header to btsnoop file (if file is still empty):
        if self.write_btsnooplog and self.btsnooplog_file.tell() == 0:
            # BT Snoop Header: btsnoop\x00, version: 1, data link type: 1002
            btsnoop_hdr = (
                b"btsnoop\x00" + p32(1, endian="big") + p32(1002, endian="big")
            )
            with self.btsnooplog_file_lock:
                self.btsnooplog_file.write(btsnoop_hdr)
                self.btsnooplog_file.flush()

        return True

    def _teardownSockets(self):
        """
        Close s_snoop and s_inject socket. (equal)
        """

        if self.s_inject is not None:
            self.s_inject.close()
            self.s_inject = None
            self.s_snoop = None

        return True
