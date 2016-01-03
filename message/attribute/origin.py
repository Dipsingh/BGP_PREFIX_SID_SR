
import struct

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep


class Origin(Attribute):
    """
        ORIGIN is a well-known mandatory attribute that defines the
    origin of the path information. The data octet can assume
    the following values:
    Value       Meaning
        0        IGP  -  Network Layer Reachability Information is interior to the originating AS
        1        EGP - Network Layer Reachability Information learned via the EGP protocol [RFC904]
        2        INCOMPLETE - Network Layer Reachability Information learned by some other means
    """

    ID = AttributeID.ORIGIN
    FLAG = AttributeFlag.TRANSITIVE
    MULTIPLE = False

    IGP = 0x00
    EGP = 0x01
    INCOMPLETE = 0x02

    @classmethod
    def parse(cls, value):
        origin = struct.unpack('!B', value)[0]
        if orgin not in [cls.IGP, cls.EGP, cls.INCOMPLETE]:
            raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_INVALID_ORIGIN,data=value)
        return origin

    @classmethod
    def construct(cls, value):
        if value not in [cls.IGP, cls.EGP, cls.INCOMPLETE]:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_INVALID_ORIGIN,data='')
        length = 1
        return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', length) + struct.pack('!B', value)

