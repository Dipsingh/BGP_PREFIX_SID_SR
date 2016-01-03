import struct
import binascii

import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep

class NextHop(Attribute):

    ID = AttributeID.NEXT_HOP
    FLAG = AttributeFlag.TRANSITIVE
    MULTIPLE = False

    @classmethod
    def parse(cls, value):
        if len(value) % 4 == 0:
            next_hop = str (socket.inet_ntoa(struct.unpack("!I",value[0:4])))
            return next_hop
        else:
            # Error process
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)


    @classmethod
    def construct(cls, value):
        try:
            if netaddr.IPAddress(value).version == 4:
                ip_addr_raw = netaddr.IPAddress(value).packed
                return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', len(ip_addr_raw)) + ip_addr_raw

            else:
                raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_INVALID_NEXTHOP,data=value)
        except Exception:
                raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_INVALID_NEXTHOP,data=value)


