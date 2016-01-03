import struct
from common.exception import MessageHeaderError
from common.constants import ERR_MSG_HDR_BAD_MSG_LEN


class KeepAlive(object):
    MSG_KEEPALIVE = 4

    @staticmethod
    def parse(msg):
        if len(msg) == 0:
            raise MessageHeaderError(sub_error=ERR_MSG_HDR_BAD_MSG_LEN,data='')


    @staticmethod
    def construct_header():
        """
        #    16-octet     2-octet  1-octet
        # ---------------+--------+---------+------+
        #    Maker       | Length |  Type   |  msg |
        # ---------------+--------+---------+------+
                              TYPE
                              1 - OPEN
                              2 - UPDATE
                              3 - NOTIFICATION
                              4 - KEEPALIVE
        """
        return b"".join((b'\xff'*16,struct.pack("!HB",19,4)))

    def construct(self):
        return self.construct_header()



