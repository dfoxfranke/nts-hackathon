import enum
import struct

class Leap(enum.IntEnum):
    NOWARNING = 0
    ADDSECOND = 1
    DELSECOND = 2
    NOTINSYNC = 3

class Mode(enum.IntEnum):
    UNSPEC = 0
    ACTIVE = 1
    PASSIVE = 2
    CLIENT = 3
    SERVER = 4
    BROADCAST = 5
    CONTROL = 6
    PRIVATE = 7

class NtpExtension:
    def __init__(self, pkt_or_typeid, body=None):
        if body is not None:
            if len(body) < 12:
                raise ValueError("Body length must be at least 12")
            if len(body) % 4 != 0:
                raise ValueError("Body length must be a multiple of 4")
            self.typeid = pkt_or_typeid
            self.body = body
            return
        pkt = pkt_or_typeid
        if len(pkt) < 16:
            raise ValueError("Extension field not long enough to be valid")
        (self.typeid, length) = struct.unpack(">HH", pkt[0:4])
        if len(pkt) < length:
            raise ValueError("Extension field shorter than indicated length")
        if length < 16:
            raise ValueError("Extension field length too short")
        if length % 4 != 0:
            raise ValueError("Extension field length must be a multiple of 4")
        self.body = pkt[4:length-4]

    def __bytes__(self):
        return struct.pack(">HH", self.typeid, len(self.body) + 4) + self.body

    def __len__(self):
        return len(self.body) + 4

class NtpPacket:
    def __init__(self, pkt=None):
        self.li = Leap.NOTINSYNC
        self.vn = 4
        self.mode = Mode.UNSPEC
        self.stratum = 0
        self.ppoll = 0
        self.precision = 0
        self.rootdelay = 0
        self.rootdisp = 0
        self.refid = b"\0\0\0\0"
        self.reftime = 0
        self.org = 0
        self.rec = 0
        self.xmt = 0
        self.extensions = []

        if pkt is None:
            return

        pkt = bytes(pkt) #Make immutable to avoid O(n^2) parsing
        
        if len(pkt) < 48:
            raise ValueError("Packet too short")

        if len(pkt) % 4 != 0:
            raise ValueError("Packet length must be a multiple of 4")

        (li_vn_mode, self.stratum, self.ppoll, self.precision,
         self.rootdelay, self.rootdisp, self.refid, self.reftime,
         self.org, self.rec, self.xmt) = struct.unpack(
             ">BBBBII4sQQQQ", pkt[0:48])

        self.li = Leap(li_vn_mode >> 6)
        self.vn = (li_vn_mode >> 3) & 0x7
        self.mode = Mode(li_vn_mode & 0x7)

        if(self.vn > 4):
            raise ValueError("Unsupported packet version")

        if(self.vn != 4):
            return

        pkt = pkt[48:]
        while len(pkt) >= 28:
            ext = NtpExtension(pkt)
            self.extensions.append(ext)
            pkt = pkt[len(ext):]

    def __bytes__(self):
        return struct.pack(">BBBBII4sQQQQ",
                           int(self.li) << 6 | 4 << 3 | int(self.mode),
                           self.stratum, self.ppoll, self.precision,
                           self.rootdelay, self.rootdisp,
                           self.refid, self.reftime,
                           self.org, self.rec, self.xmt) + \
            b''.join(self.extensions)
