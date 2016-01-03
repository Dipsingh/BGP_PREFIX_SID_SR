

import struct

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep

class LocalPreference(Attribute):
    """LOCAL_PREF is a well-known attribute that is a four-octet
    unsigned integer. A BGP speaker uses it to inform its other
    internal peers of the advertising speaker's degree of
    preference for an advertised route.
    """

    ID = AttributeID.LOCAL_PREF
    FLAG = AttributeFlag.TRANSITIVE
    MULTIPLE = False

    @classmethod
    def parse(cls, value):
        """
        parse bgp local preference attribute
        :param value: raw binary value
        """
        try:
            return struct.unpack('!I', value)[0]
        except:
            raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN, data=value)

    @classmethod
    def construct(cls, value):
        """
        encode bgp local preference attribute
        :param value: interger value
        """
        try:
            return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', 4) + struct.pack('!I', value)
        except Exception:
            raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data='')
