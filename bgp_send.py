import struct
from message.open import Open as Open

class BGPSend(object):

    def bgp_send_message(self,message):
        self.bgp_send_open()



    def bgp_send_open(self):
        open=Open(version=4, asn=1,bgp_id=None)
        open.construct()
