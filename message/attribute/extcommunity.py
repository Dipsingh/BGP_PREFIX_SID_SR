
import struct
import logging
import binascii

import netaddr

from message.attribute.attribute_base import Attribute
from message.attribute.attribute_base import AttributeFlag
from message.attribute.attribute_base import AttributeID
from common import exception as excep
from common import constants as bgp_cons

LOG = logging.getLogger()


class ExtCommunity(Attribute):

    """
        Each Extended Community is encoded as an 8-octet quantity, as
        follows:
        - Type Field : 1 or 2 octets
        - Value Field : Remaining octets
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Type high | Type low(*) |                                     |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Value                         |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        Parse Extended Community attributes.
    """


    @classmethod
    def parse(cls, value):
        if len(value) % 8 != 0:
            raise excep.UpdateMessageError(sub_error=bgp_cons.ERR_MSG_UPDATE_ATTR_LEN,data=value)

        ext_community = []
        while value:
            comm_type, subtype = struct.unpack('!BB', value[0:2])
            value_tmp = value[2:8]

            comm_code = comm_type * 256 + subtype

            if comm_code == bgp_cons.BGP_EXT_COM_RT_0:
                # Route Target, Format AS(2bytes):AN(4bytes)
                asn, an = struct.unpack('!HI', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_COM_RT_0, '%s:%s' % (asn, an)])

            elif comm_code == bgp_cons.BGP_EXT_COM_RT_1:
                # Route Target,Format IPv4 address(4bytes):AN(2bytes)
                ipv4 = str(netaddr.IPAddress(struct.unpack('!I', value_tmp[0:4])[0]))
                an = struct.unpack('!H', value_tmp[4:])[0]
                ext_community.append([bgp_cons.BGP_EXT_COM_RT_1, '%s:%s' % (ipv4, an)])

            elif comm_code == bgp_cons.BGP_EXT_COM_RT_2:
                # Route Target,Format AS(4bytes):AN(2bytes)
                asn, an = struct.unpack('!IH', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_COM_RT_2, '%s:%s' % (asn, an)])

            elif comm_code == bgp_cons.BGP_EXT_COM_RO_0:
                # Route Origin,Format AS(2bytes):AN(4bytes)
                asn, an = struct.unpack('!HI', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_COM_RO_0, '%s:%s' % (asn, an)])

            elif comm_code == bgp_cons.BGP_EXT_COM_RO_1:
                # Route Origin,Format IP address:AN(2bytes)
                ipv4 = str(netaddr.IPAddress(struct.unpack('!I', value_tmp[0:4])[0]))
                an = struct.unpack('!H', value_tmp[4:])[0]
                ext_community.append([bgp_cons.BGP_EXT_COM_RO_1, '%s:%s' % (ipv4, an)])

            elif comm_code == bgp_cons.BGP_EXT_COM_RO_2:
                # Route Origin,Format AS(2bytes):AN(4bytes)
                asn, an = struct.unpack('!IH', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_COM_RO_2, '%s:%s' % (asn, an)])

            elif comm_code == bgp_cons.BGP_EXT_REDIRECT_NH:
                ipv4 = str(netaddr.IPAddress(int(binascii.b2a_hex(value_tmp[0:4]), 16)))
                copy_flag = struct.unpack('!H', value_tmp[4:])[0]
                ext_community.append([bgp_cons.BGP_EXT_REDIRECT_NH, ipv4, copy_flag])
            elif comm_code == bgp_cons.BGP_EXT_TRA_RATE:
                asn, rate = struct.unpack('!Hf', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_TRA_RATE, '%s:%s' % (asn, int(rate))])


            """
             # BGP Flow spec
            elif comm_code == bgp_cons.BGP_EXT_REDIRECT_NH:
                ipv4 = str(netaddr.IPAddress(int(binascii.b2a_hex(value_tmp[0:4]), 16)))
                copy_flag = struct.unpack('!H', value_tmp[4:])[0]
                ext_community.append([bgp_cons.BGP_EXT_REDIRECT_NH, ipv4, copy_flag])
            elif comm_code == bgp_cons.BGP_EXT_TRA_RATE:
                asn, rate = struct.unpack('!Hf', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_TRA_RATE, '%s:%s' % (asn, int(rate))])

            elif comm_code == bgp_cons.BGP_EXT_TRA_ACTION:
                bit_value = parse_bit(value_tmp[-1])
                ext_community.append([bgp_cons.BGP_EXT_TRA_ACTION, {'S': bit_value['6'], 'T': bit_value['7']}])
            elif comm_code == bgp_cons.BGP_EXT_REDIRECT_VRF:
                asn, an = struct.unpack('!HI', value_tmp)
                ext_community.append([bgp_cons.BGP_EXT_REDIRECT_VRF, '%s:%s' % (asn, an)])
            elif comm_code == bgp_cons.BGP_EXT_TRA_MARK:
                mark = struct.unpack('!B', value_tmp[-1])[0]
                ext_community.append([bgp_cons.BGP_EXT_TRA_MARK, mark])

            else:
                ext_community.append([bgp_cons.BGP_EXT_COM_UNKNOW, repr(value_tmp)])
                LOG.warn('unknow bgp extended community, type=%s, value=%s', comm_code, repr(value_tmp))

            """
            value = value[8:]

        return ext_community


    @classmethod
    def construct(cls, value):

        """
        Construct Extended Community attributes.
        :param value: value list like [('RT':4837:9929),('RT': 1239:9929)]
        """
        ext_community_hex = b''
        for item in value:
            if item[0] == bgp_cons.BGP_EXT_COM_RT_0:
                # Route Target, Format AS(2bytes):AN(4bytes)
                asn, an = item[1].split(':')
                ext_community_hex += struct.pack('!HHI', bgp_cons.BGP_EXT_COM_RT_0, int(asn), int(an))
            elif item[0] == bgp_cons.BGP_EXT_COM_RT_1:
                ip, an = item[1].split(':')
                ext_community_hex += struct.pack('!H', bgp_cons.BGP_EXT_COM_RT_1) + netaddr.IPAddress(ip).packed + \
                    struct.pack('!H', int(an))
            elif item[0] == bgp_cons.BGP_EXT_COM_RT_2:
                asn, an = item[1].split(':')
                ext_community_hex += struct.pack('!HIH', bgp_cons.BGP_EXT_COM_RT_2, int(asn), int(an))

            # for Route Origin
            elif item[0] == bgp_cons.BGP_EXT_COM_RO_0:
                asn, an = item[1].split(':')
                ext_community_hex += struct.pack('!HHI', bgp_cons.BGP_EXT_COM_RO_0, int(asn), int(an))
            elif item[0] == bgp_cons.BGP_EXT_COM_RO_1:
                ip, an = item[1].split(':')
                ext_community_hex += struct.pack('!H', bgp_cons.BGP_EXT_COM_RO_1) + netaddr.IPAddress(ip).packed + \
                    struct.pack('!H', int(an))
            elif item[0] == bgp_cons.BGP_EXT_COM_RO_2:
                asn, an = item[1].split(':')
                ext_community_hex += struct.pack('!HIH', bgp_cons.BGP_EXT_COM_RO_2, int(asn), int(an))
            else:
                LOG.warn('unknow bgp extended community for construct, type=%s, value=%s', item[0], item[1])

        if ext_community_hex:
            return struct.pack('!B', cls.FLAG) + struct.pack('!B', cls.ID) + struct.pack('!B', len(ext_community_hex)) + ext_community_hex
        else:
            LOG.error('construct error, value=%s' % value)
            return None


    """
    def parse_bit(data):

    The operator byte is encoded as:
      0    1   2   3   4  5   6   7
    +---+---+---+---+---+---+---+---+
    | e | a |  len  | 0 |lt |gt |eq |
    +---+---+---+---+---+---+---+---+

    bit_list = []
    for i in xrange(8):
        bit_list.append((data >> i) & 1)
    bit_list.reverse()
    result = {
        '0': bit_list[0],
        '1': bit_list[1],
        '2': bit_list[2],
        '3': bit_list[3],
        '4': bit_list[4],
        '5': bit_list[5],
        '6': bit_list[6],
        '7': bit_list[7]
    }
    return result
    """




