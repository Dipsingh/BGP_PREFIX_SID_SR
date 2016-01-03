
import struct
from common import constants as bgp_cons
from common import exception as excep
from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID

class BGPPrefixSid(Attribute):

    ID = AttributeID.BGP_PREFIX_SID
    FLAG = AttributeFlag.OPTIONAL + AttributeFlag.TRANSITIVE

    @classmethod
    def parse(cls,value):
        reserved,flags,label_index = struct.unpack("!HHI",value)
        print ("BGP Prefix SID Values are",reserved,flags,label_index)

    @classmethod
    def construct(cls,value):
        bgp_prefix_pack = b''
        length =8
        resv =0
        flags =0
        bgp_prefix_index = value
        bgp_prefix_sid = struct.pack('!HHI',resv,flags,bgp_prefix_index)
        bgp_prefix_pack = struct.pack('!B',cls.FLAG) + struct.pack('!B',cls.ID) + struct.pack('!B',length)+ bgp_prefix_sid
        print ("Sending BGP Prefix PACK ",bgp_prefix_pack)
        return bgp_prefix_pack







