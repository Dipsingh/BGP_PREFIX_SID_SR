import struct

import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import constants as bgp_cons
from common import exception as excep

class ClusterList(Attribute):

    ID = AttributeID.CLUSTER_LIST
    FLAG = AttributeFlag.OPTIONAL
    MULTIPLE = False

    @classmethod
    def parse(cls, value):
        cluster_list = []
        if len(value) % 4 != 0:
               raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=repr(value))
        while value:
            cluster_list.append(str(netaddr.IPAddress(struct.unpack('!I', value[0:4])[0])))
            value = value[4:]
        return cluster_list

    @classmethod
    def construct(cls, value):
        cluster_raw = b''
        try:
            for cluster in value:
                cluster_raw += netaddr.IPAddress(cluster).packed
            return struct.pack("!B", cls.FLAG) + struct.pack('!B', cls.ID)+ struct.pack("!B", len(cluster_raw)) + cluster_raw
        except Exception:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=struct.pack('B', cls.FLAG))