
import struct

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep

class MED(Attribute):
    """
    This is an optional non-transitive attribute that is a
    four-octet unsigned integer. The value of this attribute
    MAY be used by a BGP speaker's Decision Process to
    discriminate among multiple entry points to a neighboring
    autonomous system.
    """

    ID = AttributeID.MULTI_EXIT_DISC
    FLAG = AttributeFlag.OPTIONAL
    MULTIPLE = False

    @classmethod
    def parse(cls, value):
        """
        parse BGP med attributes
        :param value: raw binary value
        """
        try:
            return struct.unpack('!I', value)[0]
        except:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)

    @classmethod
    def construct(cls, value):
        """
        encode BGP med attributes
        :param value:
        """
        try:
            return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', 4) + struct.pack('!I', value)
        except Exception:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data='')
