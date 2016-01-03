import struct
import logging
import binascii
import netaddr

from common import constants as bgp_cons


LOG = logging.getLogger(__name__)

class IPv4LabelledUnicast(object):

    """
    +---------------------------+
    | Length (1 octet)          |
    +---------------------------+
    | Label  (3 octet)          |
    +---------------------------+
    |...........................|
    +---------------------------+
    | Prefix (variable)         |
    +---------------------------+
    a) Length: The Length field indicates the length, in bits, of the address prefix.
    b) Label: (24 bits) Carries one or more labels in a stack, although a BGP update
    has only one label. This field carries the following parts of the MPLS shim header:
        Label Value–—20 Bits
        Experimental bits—3 Bits
        Bottom of stack bit—1 bit
    c) Prefix: different coding way according to different SAFI IPv4  prefix (32 bits)
    """

    @classmethod
    def parse(cls,value):
        pass

    @classmethod
    def construct(cls,bgp_prefix_sid_list):
        nlri = b''
        for prefix_label in bgp_prefix_sid_list:
            for prefix,label_value in prefix_label.items():
                nlri += cls.generate_nlri_subobj(prefix,label_value)
        return nlri



    @staticmethod
    def generate_nlri_subobj(prefix,label_value):
        packed_sub_obj = b''
        BOS=1
        label = label_value
        prefix_sid,prefix_mask = prefix.split("/")
        if int(prefix_mask) % 8 == 0:
            prefix_len = int (int(prefix_mask) / 8)
        else:
            prefix_len = int (int(prefix_mask) / 8) + 1
        length = ((prefix_len + 3) * 8) << 24
        label_stack_msg = (label << 4 | BOS)
        len_label_obj = length | label_stack_msg
        packed_len_label_obj = struct.pack("!I",len_label_obj)
        if prefix_len == 4:
            packed_ip_obj = netaddr.IPAddress(prefix_sid).packed
        elif prefix_len == 3:
            ip_obj = netaddr.IPAddress(prefix_sid)
            ip_obj1 = ip_obj >> 16
            packed_sub_ip_obj1 = struct.pack('!H',ip_obj1)
            prefix_sid1 = ip_obj & 0x0000FF00
            prefix_sid2 = prefix_sid1 >> 8
            packed_sub_ip_obj2 = struct.pack('!B',prefix_sid2)
            packed_ip_obj = packed_sub_ip_obj1+packed_sub_ip_obj2
        elif prefix_len == 2:
            ip_obj = netaddr.IPAddress(prefix_sid)
            prefix_sid1 = ip_obj >> 16
            packed_ip_obj = struct.pack('!H',prefix_sid1)
        elif prefix_len == 1:
            ip_obj = netaddr.IPAddress(prefix_sid)
            prefix_sid1 = ip_obj >> 24
            packed_ip_obj = struct.pack('!B',ip_obj)
        packed_sub_obj = packed_len_label_obj + packed_ip_obj

        return packed_sub_obj
