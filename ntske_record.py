import struct

RT_END_OF_MESSAGE = 0
RT_NEXT_PROTO_NEG = 1
RT_ERROR = 2
RT_WARNING = 3
RT_AEAD_NEG = 4
RT_NEW_COOKIE = 5 

class Record:
    def __init__(self, rec=None):
        if rec is None:
            self.critical = False
            self.rec_type = 0
            self.body = b''
            return
        if len(rec) < 4:
            raise ValueError("Record too short to be valid")
        (crit_type, body_len) = struct.unpack(">HH", rec[0:4])
        if len(rec) < body_len + 4:
            raise ValueError("Record shorter than indicated length")
        self.critical = crit_type >> 15 == 1
        self.rec_type = crit_type & 0x7fff
        self.body = rec[4:body_len+4]

    def __length__(self):
        return len(self.body)+4
        
    def __bytes__(self):
        crit_type = self.rec_type
        if self.critical:
            crit_type |= 0x8000
        return struct.pack(">HH", crit_type, len(self.body)) + self.body
