

import struct


class RouteRefresh(object):

    """
    Route Refresh message
    """

    def __init__(self, afi=None, safi=None, res=0):

        # Message Format: One <AFI, SAFI> encoded as
        # 0       7       15      23     31
        # +-------+-------+-------+-------+
        # |      AFI      | Res.  | SAFI  |
        # +-------+-------+-------+-------+

        self.afi = afi
        self.res = res
        self.safi = safi

    def parse(self, msg):

        self.afi, self.res, self.safi = struct.unpack("!HBB", msg)
        return self.afi, self.res, self.safi

    @staticmethod
    def construct_header(message, msg_type):


        #    16-octet     2-octet  1-octet
        # ---------------+--------+---------+------+
        #    Maker      | Length |  Type   |  msg |
        # ---------------+--------+---------+------+
        return b"".join((b'\xff'*16,struct.pack('!HB',len(message)+19,msg_type),message))

    def construct(self, msg_type):

        msg = struct.pack('!H', self.afi) + struct.pack('!B', self.res) + struct.pack('!B', self.safi)
        return self.construct_header(msg, msg_type)
