

import logging
import traceback
import struct
import time
import netaddr
from twisted.internet import protocol

from bgp.common import constants as bgp_cons
from bgp.message.open import Open
from bgp.message.keepalive import KeepAlive
from bgp.message.update import Update
from bgp.message.notification import Notification
from bgp.message.route_refresh import RouteRefresh
from bgp.common import exception as excep

LOG = logging.getLogger(__name__)

class BGP(protocol.Protocol):
    def __init__(self):
        self.fsm = None
        self.peer_id = None

        self.disconnected = False
        self.receive_buffer = b''
        self.fourbytesas = False
        self.add_path_ipv4_receive = False
        self.add_path_ipv4_send = False

        self.msg_sent_stat = {
            'Opens': 0,
            'Notifications': 0,
            'Updates': 0,
            'Keepalives': 0,
            'RouteRefresh': 0
        }
        self.msg_recv_stat = {
            'Opens': 0,
            'Notifications': 0,
            'Updates': 0,
            'Keepalives': 0,
            'RouteRefresh': 0
        }
        # Adj-rib-in
        self._adj_rib_in = {}

        # Adj-rib-out
        self._adj_rib_out = {}

    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        LOG.info("[%s]TCP Connection established", self.factory.peer_addr)
        






