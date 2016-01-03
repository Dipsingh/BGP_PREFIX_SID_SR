import struct
from message.open import Open as Open
from message.keepalive import KeepAlive as KeepAlive
import netaddr


class BGPHandler(object):
    def __init__(self):
        self._bgp_ka= 10

    def parse_recvd_msg(self,message):
        msg_len,msg_type,msg = self.common_header(message)
        my_capability = {'route_refresh': False, 'four_bytes_as': False, 'cisco_route_refresh': False, 'afi_safi': [(1, 4)], 'graceful_restart': False}
        if msg_type == 1:
            parsed_open_message = self.open_parse(msg)
            if parsed_open_message["Capabilities"]["afi_safi"][0] == (1,4):
                open_msg = self.send_open(my_capability)
                return open_msg
            else:
                print ("Neighbor doesnt have v4 Labelled Unicast enabled",parsed_open_message["Capabilities"]["afi_safi"][0])

    def common_header(self,message):
        length,msg_type = struct.unpack('!HB',message[16:19])
        return (length,msg_type,message[19:])

    def open_parse(self,message):
        open = Open(version=4, asn=1,bgp_id=None)
        parsed_open_message = open.parse(message)
        return (parsed_open_message)

    def send_open(self,my_capability):
        open=Open(version=4, asn=1,hold_time=180,bgp_id='172.16.2.1')
        open_msg= open.construct(my_capability)
        return open_msg

    def bgp_send_ka(self):
        keepalive = KeepAlive()
        return (keepalive.construct())





