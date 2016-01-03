
import binascii
import struct
import socket
import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import exception as excep
from common import constants as bgp_cons


class OriginatorID(Attribute):

    ID = AttributeID.ORIGINATOR_ID
    FLAG = AttributeFlag.OPTIONAL

    @classmethod
    def parse(cls, value):

        if len(value) != 4:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)
        return str (socket.inet_ntoa(struct.unpack("!I",value[0:4])))

    @classmethod
    def construct(cls,value):
        try:
            return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', 4) + struct.pack('!I',int(netaddr.IPAddress(ip)))
        except Exception:
            raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)





