
import struct

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import exception as excep
from common import constants as bgp_cons


class Community(Attribute):

    ID = AttributeID.COMMUNITY
    FLAG = AttributeFlag.OPTIONAL + AttributeFlag.TRANSITIVE

    @classmethod
    def parse(cls, value):
        if not value:
            return value
        else:
            raise ("Community Parse Error")


    @classmethod
    def construct(cls, value):
        if not value:
            return value
        else:
            raise ("Community Construct Error")

