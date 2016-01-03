
import struct
import traceback
import logging
import netaddr

from common import exception as excep
from common import constants as bgp_cons
from message.attribute.attribute_base import AttributeFlag as AttributeFlag
from message.attribute.origin import Origin
from message.attribute.aspath import ASPath
from message.attribute.nexthop import NextHop
from message.attribute.med import MED
from message.attribute.localpref import LocalPreference
from message.attribute.atomicaggregate import AtomicAggregate
from message.attribute.aggregator import Aggregator
from message.attribute.community import Community
from message.attribute.originatorid import OriginatorID
from message.attribute.clusterlist import ClusterList
from message.attribute.extcommunity import ExtCommunity
from message.attribute.mpreachnlri import MpReachNLRI
from message.attribute.bgpprefixsid import BGPPrefixSid

LOG = logging.getLogger()

class Update(object):
    def __init__(self):
        _test = 0

    @classmethod
    def parse(cls, t, msg_hex, asn4=False, add_path_remote=False, add_path_local=False):

        """
        Parse BGP Update message
        :param t: timestamp
        :param msg_hex: raw message
        :param asn4: support 4 bytes AS or not
        :param add_path_remote: if the remote peer can send add path NLRI
        :param add_path_local: if the local can send add path NLRI
        :return: message after parsing.
        """
        results = {
            "withdraw": [],
            "attr": None,
            "nlri": [],
            'time': t,
            'hex': msg_hex,
            'sub_error': None,
            'err_data': None
        }

        # get every part of the update message
        withdraw_len = struct.unpack('!H', msg_hex[:2])[0]
        withdraw_prefix_data = msg_hex[2:withdraw_len + 2]
        attr_len = struct.unpack('!H', msg_hex[withdraw_len + 2:withdraw_len + 4])[0]
        attribute_data = msg_hex[withdraw_len + 4:withdraw_len + 4 + attr_len]
        nlri_data = msg_hex[withdraw_len + 4 + attr_len:]

        try:
            # parse withdraw prefixes
            results['withdraw'] = cls.parse_prefix_list(withdraw_prefix_data, add_path_remote)

            # parse nlri
            results['nlri'] = cls.parse_prefix_list(nlri_data, add_path_remote)
        except Exception as e:
            LOG.error(e)
            error_str = traceback.format_exc()
            LOG.debug(error_str)
            results['sub_error'] = bgp_cons.ERR_MSG_UPDATE_INVALID_NETWORK_FIELD
            results['err_data'] = ''
        try:
            # parse attributes
            results['attr'] = cls.parse_attributes(attribute_data, asn4)
        except excep.UpdateMessageError as e:
            LOG.error(e)
            results['sub_error'] = e.sub_error
            results['err_data'] = e.data
        except Exception as e:
            LOG.error(e)
            error_str = traceback.format_exc()
            LOG.debug(error_str)
            results['sub_error'] = e
            results['err_data'] = e

        return results

    @classmethod
    def construct(cls, msg_dict, asn4=False, addpath=False):
        """

        """
        attr_hex = b''
        nlri_hex = b''
        withdraw_hex = b''
        if msg_dict.get('attr'):
            attr_hex = cls.construct_attributes(msg_dict['attr'], asn4)
        if msg_dict.get('nlri'):
            nlri_hex = cls.construct_prefix_v4(msg_dict['nlri'], addpath)
        if msg_dict.get('withdraw'):
            withdraw_hex = cls.construct_prefix_v4(msg_dict['withdraw'], addpath)
        if nlri_hex and attr_hex:
            msg_body = struct.pack('!H', 0) + struct.pack('!H', len(attr_hex)) + attr_hex + nlri_hex
            return cls.construct_header(msg_body)
        elif attr_hex and not nlri_hex:
            msg_body = struct.pack('!H', 0) + struct.pack('!H', len(attr_hex)) + attr_hex + nlri_hex
            return cls.construct_header(msg_body)
        elif withdraw_hex:
            msg_body = struct.pack('!H', len(withdraw_hex)) + withdraw_hex + struct.pack('!H', 0)
            return cls.construct_header(msg_body)

    @staticmethod
    def parse_prefix_list(data, addpath=False):
        """
        Parses an RFC4271 encoded blob of BGP prefixes into a list

        :param data: hex data
        :param addpath: support addpath or not
        :return: prefix_list
        """
        prefixes = []
        postfix = data
        while len(postfix) > 0:
            # for python2 and python3
            if addpath:
                path_id = struct.unpack('!I', postfix[0:4])[0]
                postfix = postfix[4:]
            if isinstance(postfix[0], int):
                prefix_len = postfix[0]
            else:
                prefix_len = ord(postfix[0])
            if prefix_len > 32:
                LOG.warning('Prefix Length larger than 32')
                raise excep.UpdateMessageError(
                    sub_error=bgp_cons.ERR_MSG_UPDATE_INVALID_NETWORK_FIELD,
                    data=repr(data)
                )
            octet_len, remainder = int(prefix_len / 8), prefix_len % 8
            if remainder > 0:
                # prefix length doesn't fall on octet boundary
                octet_len += 1
            tmp = postfix[1:octet_len + 1]
            # for python2 and python3
            if isinstance(postfix[0], int):
                prefix_data = [i for i in tmp]
            else:
                prefix_data = [ord(i) for i in tmp]
            # Zero the remaining bits in the last octet if it didn't fall
            # on an octet boundary
            if remainder > 0:
                prefix_data[-1] &= 255 << (8 - remainder)
            prefix_data = prefix_data + list(str(0)) * 4
            prefix = "%s.%s.%s.%s" % (tuple(prefix_data[0:4])) + '/' + str(prefix_len)
            if not addpath:
                prefixes.append(prefix)
            else:
                prefixes.append({'prefix': prefix, 'path_id': path_id})
            # Next prefix
            postfix = postfix[octet_len + 1:]

        return prefixes

    @staticmethod
    def parse_attributes(data, asn4=False):
        """
        Parses an RFC4271 encoded blob of BGP attributes into a list

        :param data:
        :param asn4: support 4 bytes asn or not
        :return:
        """
        attributes = {}
        postfix = data
        while len(postfix) > 0:

            try:
                flags, type_code = struct.unpack('!BB', postfix[:2])

                if flags & AttributeFlag.EXTENDED_LENGTH:
                    attr_len = struct.unpack('!H', postfix[2:4])[0]
                    attr_value = postfix[4:4 + attr_len]
                    postfix = postfix[4 + attr_len:]    # Next attribute
                else:    # standard 1-octet length
                    if isinstance(postfix[2], int):
                        attr_len = postfix[2]
                    else:
                        attr_len = ord(postfix[2])
                    attr_value = postfix[3:3 + attr_len]
                    postfix = postfix[3 + attr_len:]    # Next attribute
            except Exception as e:
                LOG.error(e)
                error_str = traceback.format_exc()
                LOG.debug(error_str)
                raise excep.UpdateMessageError(
                    sub_error=bgp_cons.ERR_MSG_UPDATE_MALFORMED_ATTR_LIST,
                    data='')

            if type_code == bgp_cons.BGPTYPE_ORIGIN:

                decode_value = Origin.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_AS_PATH:

                decode_value = ASPath.parse(value=attr_value, asn4=asn4)

            elif type_code == bgp_cons.BGPTYPE_NEXT_HOP:

                decode_value = NextHop.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_MULTI_EXIT_DISC:

                decode_value = MED.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_LOCAL_PREF:

                decode_value = LocalPreference.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_ATOMIC_AGGREGATE:

                decode_value = AtomicAggregate.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_AGGREGATOR:

                decode_value = Aggregator.parse(value=attr_value, asn4=asn4)

            elif type_code == bgp_cons.BGPTYPE_COMMUNITIES:

                decode_value = Community.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_ORIGINATOR_ID:

                decode_value = OriginatorID.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_CLUSTER_LIST:

                decode_value = ClusterList.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_NEW_AS_PATH:

                decode_value = ASPath.parse(value=attr_value, asn4=True)

            elif type_code == bgp_cons.BGPTYPE_NEW_AGGREGATOR:

                decode_value = Aggregator.parse(value=attr_value, asn4=True)

            elif type_code == bgp_cons.BGPTYPE_MP_REACH_NLRI:
                decode_value = MpReachNLRI.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_MP_UNREACH_NLRI:
                decode_value = MpUnReachNLRI.parse(value=attr_value)

            elif type_code == bgp_cons.BGPTYPE_EXTENDED_COMMUNITY:
                decode_value = ExtCommunity.parse(value=attr_value)
            else:
                decode_value = repr(attr_value)
            attributes[type_code] = decode_value

        return attributes

    @staticmethod
    def construct_attributes(attr_dict, asn4=False):

        """

        """
        attr_raw_hex = b''
        for type_code, value in attr_dict.items():

            if int(type_code) == bgp_cons.BGPTYPE_ORIGIN:
                origin_hex = Origin.construct(value=value)
                attr_raw_hex += origin_hex

            elif int(type_code) == bgp_cons.BGPTYPE_AS_PATH:
                aspath_hex = ASPath.construct(value=value, asn4=asn4)
                attr_raw_hex += aspath_hex

            elif int(type_code) == bgp_cons.BGP_PREFIX_SID:
                prefix_sid_hex = BGPPrefixSid.construct(value=value)
                attr_raw_hex += prefix_sid_hex

            elif int(type_code) == bgp_cons.BGPTYPE_NEXT_HOP:
                nexthop_hex = NextHop.construct(value=value)
                attr_raw_hex += nexthop_hex

            elif int(type_code) == bgp_cons.BGPTYPE_MULTI_EXIT_DISC:
                med_hex = MED.construct(value=value)
                attr_raw_hex += med_hex

            elif int(type_code) == bgp_cons.BGPTYPE_LOCAL_PREF:
                localpre_hex = LocalPreference.construct(value=value)
                attr_raw_hex += localpre_hex

            elif int(type_code) == bgp_cons.BGPTYPE_ATOMIC_AGGREGATE:
                atomicaggregate_hex = AtomicAggregate.construct(value=value)
                attr_raw_hex += atomicaggregate_hex

            elif int(type_code) == bgp_cons.BGPTYPE_AGGREGATOR:
                aggregator_hex = Aggregator.construct(value=value, asn4=asn4)
                attr_raw_hex += aggregator_hex

            elif int(type_code) == bgp_cons.BGPTYPE_COMMUNITIES:
                community_hex = Community.construct(value=value)
                attr_raw_hex += community_hex

            elif int(type_code) == bgp_cons.BGPTYPE_ORIGINATOR_ID:
                originatorid_hex = OriginatorID.construct(value=value)
                attr_raw_hex += originatorid_hex

            elif int(type_code) == bgp_cons.BGPTYPE_CLUSTER_LIST:
                clusterlist_hex = ClusterList.construct(value=value)
                attr_raw_hex += clusterlist_hex

            elif int(type_code) == bgp_cons.BGPTYPE_MP_REACH_NLRI:
                mpreach_hex = MpReachNLRI().construct(value=value)
                attr_raw_hex += mpreach_hex
            elif int(type_code) == bgp_cons.BGPTYPE_MP_UNREACH_NLRI:
                mpunreach_hex = MpUnReachNLRI.construct(value=value)
                attr_raw_hex += mpunreach_hex
            elif int(type_code) == bgp_cons.BGPTYPE_EXTENDED_COMMUNITY:
                community_ext_hex = ExtCommunity.construct(value=value)
                attr_raw_hex += community_ext_hex

        return attr_raw_hex

    @staticmethod
    def construct_header(msg):
        """
        """
        #    16-octet     2-octet  1-octet
        # ---------------+--------+---------+------+
        #    Maker      | Length |  Type   |  msg |
        # ---------------+--------+---------+------+
        return b'\xff'*16 + struct.pack('!HB', len(msg) + 19, 2) + msg

    @staticmethod
    def construct_prefix_v4(prefix_list, add_path=False):
        """
        constructs NLRI prefix list

        :param prefix_list: prefix list
        :param add_path: support add path or not
        """
        nlri_raw_hex = b''
        for prefix in prefix_list:
            if add_path and isinstance(prefix, dict):
                path_id = prefix.get('path_id')
                prefix = prefix.get('prefix')
                nlri_raw_hex += struct.pack('!I', path_id)
            masklen = prefix.split('/')[1]
            ip_hex = struct.pack('!I', netaddr.IPNetwork(prefix).value)
            masklen = int(masklen)
            if 16 < masklen <= 24:
                ip_hex = ip_hex[0:3]
            elif 8 < masklen <= 16:
                ip_hex = ip_hex[0:2]
            elif masklen <= 8:
                ip_hex = ip_hex[0:1]
            nlri_raw_hex += struct.pack('!B', masklen) + ip_hex
        return nlri_raw_hex




