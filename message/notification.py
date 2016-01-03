import struct

class Notification(object):
    MSG_NOTIFICATION = 3
    COMMON_MARKER = b'\xff'*16

    @staticmethod
    def parse(message):
        """
         Parse Input Notification message which is indicative of Error
         0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Error code    | Error subcode |   Data (variable)             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        error, suberror = struct.unpack('!BB', message[:2])

    @classmethod
    def construct_header(cls, message):
        '''
         """
        #    16-octet     2-octet  1-octet
        # ---------------+--------+---------+------+
        #    Maker      | Length |  Type   |  msg |
        # ---------------+--------+---------+------+
         0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      | Error code    | Error subcode |   Data (variable)             |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        TYPE
                              1 - OPEN
                              2 - UPDATE
                              3 - NOTIFICATION
                              4 - KEEPALIVE
        '''
        return b"".join(cls.COMMON_MARKER + struct.pack('!HB',len(message)+19,cls.MSG_NOTIFICATION)+message)

    def construct(self, error, suberror=0, data=b''):
        msg = struct.pack('!BB', error, suberror) + data
        return self.construct_header(msg)




