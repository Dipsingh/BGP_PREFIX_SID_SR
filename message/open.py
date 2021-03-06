import struct
import netaddr

from common import exception as excp
from common import constants as bgp_cons

class Open(object):
    def __init__(self, version=None, asn=None, hold_time=None,bgp_id=None, opt_para_len=None, opt_paras=None):

        # 1-octet
        # +-----------+
        # | Version   |
        # +-----------+-----------+
        # | My Autonomous System  |
        # +-----------+-----------+
        # |       Hold Time       |
        # +-----------+-----------+-----------+-----------+
        # |                BGP Identifier                 |
        # +-----------+-----------+-----------+-----------+
        # |OptParm Len|
        # +-----------+-----------+-----------+-----------+
        # | Optional Parameters (variable)                |
        # +-----------+-----------+-----------+-----------+

        self.version = version
        self.asn = asn
        self.hold_time = hold_time
        self.bgp_id = bgp_id
        self.opt_para_len = opt_para_len
        self.opt_paras = opt_paras
        self.capa_dict = {}
        # used to store Capabilities {code: value}


    def parse(self,message):

        try:
            self.version, self.asn, self.hold_time,self.bgp_id, self.opt_para_len = struct.unpack('!BHHIB', message[:10])

        except:
            raise excp.MessageHeaderError(sub_error=bgp_cons.ERR_MSG_HDR_BAD_MSG_LEN, data=message[:10])

        self.bgp_id = str(netaddr.IPAddress(self.bgp_id))

        if self.version != 4:
            # Here we just support BGP-4
            raise excp.OpenMessageError( sub_error=bgp_cons.ERR_MSG_OPEN_UNSUP_VERSION, data=self.version)

        if isinstance(self.asn, float):
            self.asn = str(self.asn).split('.')
            self.asn = 65536 * (int(self.asn[0])) + int(self.asn[1])

        if self.asn in (0, 2 ** 16 - 1):
            # bad peer asn
            raise excp.OpenMessageError(sub_error=bgp_cons.ERR_MSG_OPEN_BAD_PEER_AS,data=self.asn)
        # Hold Time negotiation is out of this scope

        if self.bgp_id in (0, 2 ** 32 - 1):
            raise excp.OpenMessageError(sub_error=bgp_cons.ERR_MSG_OPEN_BAD_BGP_ID,data=self.bgp_id)
        # Optional Parameters
        if self.opt_para_len:

            self.opt_paras = message[10:]

            # While Loop: Parse one Optional Parameter(Capability) each time
            while self.opt_paras:

                # 1 octet     1 octet      variable
                # --------------------------------------+
                # para_type | para_length | para_value |
                # --------------------------------------+
                opt_para_type, opt_para_length = struct.unpack('!BB', self.opt_paras[:2])

                # Parameter Type 1: Authentication (deprecated) [RFC4271] [RFC5492]
                # Parameter Type 2: Capabilities [RFC5492]
                # Here we only support Type 2
                if opt_para_type != 2:
                    # if type is not type 2, return an suberror used to Notification
                    raise excp.OpenMessageError(sub_error=bgp_cons.ERR_MSG_OPEN_UNSUP_OPT_PARAM,data=message[10:])

                # ----------------------  Parse Capabilities ------------------#
                # capabilities belongs to one Optional Parameter Capability
                capabilities = self.opt_paras[2:opt_para_length + 2]

                while capabilities:

                    # ---- Parse every capability in this Optional Parameter
                    capability = Capability()
                    capability.parse(capabilities)

                    # (1) for 4 bytes ASN
                    if capability.capa_code == capability.FOUR_BYTES_ASN:
                        asn = struct.unpack('!I', capability.capa_value)[0]
                        self.asn = asn
                        self.capa_dict['four_bytes_as'] = True

                    # (2) Multiprotocol Extensions for BGP-4
                    elif capability.capa_code == capability.MULTIPROTOCOL_EXTENSIONS:
                        if 'afi_safi' not in self.capa_dict:
                            self.capa_dict['afi_safi'] = []
                        afi, res, safi = struct.unpack('!HBB', capability.capa_value)
                        self.capa_dict['afi_safi'].append((afi, safi))

                    # (3) Route Refresh
                    elif capability.capa_code == capability.ROUTE_REFRESH:
                        self.capa_dict['route_refresh'] = True

                    # (4) Cisco Route Refresh
                    elif capability.capa_code == capability.CISCO_ROUTE_REFRESH:
                        self.capa_dict['cisco_route_refresh'] = True

                    # (5) Graceful Restart
                    elif capability.capa_code == capability.GRACEFUL_RESTART:
                        self.capa_dict['graceful_restart'] = True

                    # (6) Cisco MultiSession
                    elif capability.capa_code == capability.CISCO_MULTISESSION_BGP:
                        self.capa_dict['cisco_multi_session'] = True

                    # (7) enhanced route refresh
                    elif capability.capa_code == capability.ENHANCED_ROUTE_REFRESH:
                        self.capa_dict['enhanced_route_refresh'] = True
                    # (8) add path
                    elif capability.capa_code == capability.ADD_PATH:
                        afi, safi, send_rev = struct.unpack('!HBB', capability.capa_value)
                        self.capa_dict['add_path'] = '%s_%s' % (bgp_cons.AFI_SAFI_DICT[(afi, safi)], bgp_cons.ADD_PATH_ACT_DICT[send_rev])
                    else:
                        self.capa_dict[str(capability.capa_code)] = capability.capa_value

                    capabilities = capabilities[2 + capability.capa_length:]

                # Go to next Optional Parameter
                self.opt_paras = self.opt_paras[opt_para_length + 2:]

            return {'Version': self.version,'ASN': self.asn,'holdTime': self.hold_time,'bgpID': self.bgp_id,'Capabilities': self.capa_dict}

    @staticmethod
    def construct_header(msg):
        """Prepends the mandatory header to a constructed BGP message
        # 16-octet     2-octet  1-octet
        #---------------+--------+---------+------+
        #    Maker      | Length |  Type   |  msg |
        #---------------+--------+---------+------+
        """
        return b"".join((b'\xff'*16,struct.pack('!HB',len(msg) + 19,1), msg))

    def construct(self, my_capability):
        """ Construct a BGP Open message """
        capas = b''
        if 'afi_safi' in my_capability:
            # Multiprotocol extentions capability
            capas += Capability(capa_code=1, capa_length=4).construct(my_capability)
        elif my_capability.get('cisco_route_refresh'):
            # Cisco Route refresh capability
            capas += Capability(capa_code=128, capa_length=0).construct(my_capability)
        elif my_capability.get('route_refresh'):
            # Route Refresh capability
            capas += Capability(capa_code=2, capa_length=0).construct(my_capability)
            # 4 bytes ASN

        elif self.asn > 65535:
            capas += Capability(capa_code=65, capa_length=4, capa_value=self.asn).construct(my_capability)
            self.asn = 23456
        elif my_capability.get('four_bytes_as'):
            capas += Capability(capa_code=65, capa_length=4, capa_value=self.asn).construct(my_capability)
        # for add path
        elif my_capability.get('add_path'):
            capas += Capability(capa_code=69, capa_length=4, capa_value=my_capability['add_path']).construct()

        elif my_capability.get('enhanced_route_refresh'):
            capas += Capability(capa_code=70, capa_length=0).construct()

        print ("Printing Variables",self.version, self.asn, self.hold_time,netaddr.IPAddress(self.bgp_id), len(capas))
        open_header = struct.pack('!BHHIB', self.version, self.asn, self.hold_time,netaddr.IPAddress(self.bgp_id), len(capas))
        message = open_header + capas
        return self.construct_header(message)

class Capability(object):
    RESERVED = 0x00  # [RFC5492]
    MULTIPROTOCOL_EXTENSIONS = 0x01  # [RFC2858]
    ROUTE_REFRESH = 0x02  # [RFC2918]
    OUTBOUND_ROUTE_FILTERING = 0x03  # [RFC5291]
    MULTIPLE_ROUTES = 0x04  # [RFC3107]
    EXTENDED_NEXT_HOP = 0x05  # [RFC5549]
    # 6-63      Unassigned
    GRACEFUL_RESTART = 0x40  # [RFC4724]
    FOUR_BYTES_ASN = 0x41  # [RFC4893]
    # 66 Deprecated
    DYNAMIC_CAPABILITY = 0x43  # [Chen]
    MULTISESSION_BGP = 0x44  # [Appanna]
    ADD_PATH = 0x45  # [draft-ietf-idr-add-paths]
    ENHANCED_ROUTE_REFRESH = 0x46
    # 70-127    Unassigned
    CISCO_ROUTE_REFRESH = 0x80  # I Can only find reference to this in the router logs
    # 128-255   Reserved for Private Use [RFC5492]
    CISCO_MULTISESSION_BGP = 0x83  # [Multisession BGP draft-ietf-idr-bgp-multisession-06]
    unassigned = range(70, 128)
    reserved = range(128, 256)

    def __init__(self, capa_code=None, capa_length=None, capa_value=None):

        self.capa_code = capa_code
        self.capa_length = capa_length
        self.capa_value = capa_value
    def parse(self, message):
        """
        Partition Capabilities message one by one
        """
        try:
            self.capa_code, self.capa_length = struct.unpack('!BB', message[:2])
        except:
            raise excp.OpenMessageError(sub_error=bgp_cons.ERR_MSG_HDR_BAD_MSG_LEN,data=message[:2])
        self.capa_value = message[2:self.capa_length + 2]

    def construct(self, my_capability=None):
        """ Construct a capability PDU """
        if self.capa_code == self.FOUR_BYTES_ASN:
            return struct.pack('!BBBBI', 2, 6, self.FOUR_BYTES_ASN, self.capa_length, self.capa_value)

        elif self.capa_code == self.ROUTE_REFRESH:
            return struct.pack('!BBBB', 2, 2, self.ROUTE_REFRESH, 0)

        # for cisco route refresh
        elif self.capa_code == self.CISCO_ROUTE_REFRESH:
            return struct.pack('!BBBB', 2, 2, self.CISCO_ROUTE_REFRESH, 0)

        # graceful restart
        ###Have to check the length parameter of this code...
        elif self.capa_code == self.GRACEFUL_RESTART:
            return struct.pack('!BBBB', 2, 2, self.GRACEFUL_RESTART, 0)

        # for multiprotocol extentions
        elif self.capa_code == self.MULTIPROTOCOL_EXTENSIONS:
            # <ipv4,unicast> and <ipv4,mplsvpn>
            afisafi = b''
            for (afi, safi) in my_capability['afi_safi']:
                afisafi += struct.pack('!BBBBHBB', 2, 6, self.MULTIPROTOCOL_EXTENSIONS, 4, afi, 0, safi)
            return afisafi
        # for add path
        elif self.capa_code == self.ADD_PATH:
            afi_safi, value = convert_addpath_str_to_int(self.capa_value)
            add_path = struct.pack('!BBBBHBB', 2, 6, self.ADD_PATH, self.capa_length, afi_safi[0], afi_safi[1], value)
            return add_path

        elif self.capa_code == self.ENHANCED_ROUTE_REFRESH:
            return struct.pack('!BBBB', 2, 2, self.ENHANCED_ROUTE_REFRESH, 0)

    def convert_addpath_str_to_int(addpath_str):
        addpath_dict = {
            'ipv4_receive': [(1, 1), 1],
            'ipv4_send': [(1, 1), 2],
            'ipv4_both': [(1, 1), 3]
        }
        return addpath_dict[addpath_str]

















