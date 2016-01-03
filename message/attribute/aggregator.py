
import struct

import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep


class Aggregator(Attribute):
    ID = AttributeID.AGGREGATOR
    FLAG = AttributeFlag.OPTIONAL + AttributeFlag.TRANSITIVE

    @classmethod
    def parse(cls, value, asn4=False):

        if not asn4:
            try:
                asn = struct.unpack('!H', value[:2])[0]
                aggregator = str(netaddr.IPAddress(struct.unpack('!I', value[2:])[0]))
            except Exception:
                raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)

        else:
            # 4 bytes ASN
            try:
                asn = struct.unpack('!I', value[:4])[0]
                aggregator = str(netaddr.IPAddress(struct.unpack('!I', value[4:])[0]))
            except Exception:
                raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)

        return asn, aggregator

    @classmethod
    def construct(cls, value, asn4=False):
        try:
            if asn4:
                agg_raw = struct.pack('!I', value[0]) + netaddr.IPAddress(value[1]).packed
            else:
                agg_raw = struct.pack('!H', value[0]) + netaddr.IPAddress(value[1]).packed

            return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', len(agg_raw)) + agg_raw
        except Exception:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)

