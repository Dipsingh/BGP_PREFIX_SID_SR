
import struct
import binascii

import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from message.attribute.nlri.labelledunicast import IPv4LabelledUnicast
from common import afn
from common import safn
from common import exception as excep
from common import constants as bgp_cons


class MpReachNLRI(Attribute):
    FLAG = AttributeFlag.OPTIONAL + AttributeFlag.EXTENDED_LENGTH
    afi, safi = 1,4
    ID = AttributeID.MP_REACH_NLRI
    spa=0

    @classmethod
    def parse(cls,value):
        pass

    @classmethod
    def construct(cls, value):
        """Construct a attribute
        :param value: python dictionary
        {'afi_safi': (1,128),
         'nexthop': {},
         'nlri': []
        """

        next_hop_length = 4
        nlri = IPv4LabelledUnicast.construct(value["BGP_PREFIX_SID"])
        length = 9 +len(nlri)
        return (struct.pack ('!B',cls.FLAG) + struct.pack('!B',cls.ID) + struct.pack('!H',length) + struct.pack('!H',cls.afi) +struct.pack('!B',cls.safi) + struct.pack('!B',next_hop_length) + netaddr.IPAddress(value["next_hop"]).packed + struct.pack('!B',cls.spa) + nlri)


