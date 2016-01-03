import struct

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep


class AtomicAggregate(Attribute):
    """
    ATOMIC_AGGREGATE is a well-known discretionary attribute of length 0.
    """

    ID = AttributeID.ATOMIC_AGGREGATE
    FLAG = AttributeFlag.TRANSITIVE

    @classmethod
    def parse(cls, value):

        """
        parse bgp ATOMIC_AGGREGATE attribute
        :param value:
        """
        if not value:
            return value
        else:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_OPTIONAL_ATTR,data=value)

    @classmethod
    def construct(cls, value):
        """construct a ATOMIC_AGGREGATE path attribute
        :param value:
        """

        if value:
            raise excep.UpdateMessageError( sub_error=bgp_cons.ERR_MSG_UPDATE_OPTIONAL_ATTR,data='')
        else:
            value = 0
        return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', value)
