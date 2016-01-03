__author__ = 'dipsingh'

import json
import socket
import gevent
import json
import time
from bgp_parse import BGPHandler as BGPHandler
from bgp_send import BGPSend as BGPSend
from message.update import Update
from gevent import monkey
monkey.patch_socket()

MAXCLIENTS = 10
BGPADDR='0.0.0.0'
BGPPORT=179

def send_bgp_ka(client_sock,bgp_handler):
    while True:
        client_sock.send(bgp_handler.bgp_send_ka())
        print ("KeepAlive Sent")
        gevent.sleep(bgp_handler._bgp_ka)

def parse_config(pce_config_file):
    bgp_prefix_sid_list = list()
    with open(pce_config_file) as data_file:
        msg_dict= json.load(data_file)
    for key in msg_dict:
        if key == 'BGP_PREFIX_SID':
            for prefix_sid in data[key]:
                for bgp_prefix in prefix_sid:
                    bgp_prefix_sid_list.append((bgp_prefix,prefix_sid[bgp_prefix]))
    return (tuple(bgp_prefix_sid_list),msg_dict)



def bgp_handler(client_sock,parsed_prefix_list,msg_dict):
    print ("Message Recieved from ",client_sock[1])
    bgp_handler= BGPHandler()
    bgp_send = BGPSend()
    message_recvd = client_sock[0].recv(1000)
    open_msg=bgp_handler.parse_recvd_msg(message_recvd)
    client_sock[0].send(open_msg)
    ka_greenlet = gevent.spawn(send_bgp_ka,client_sock[0],bgp_handler)

    send_upd_msg = Update.construct(msg_dict)
    print ("sending Update Message",send_upd_msg)
    client_sock[0].send(send_upd_msg)



def main ():
    bgp_server_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    parsed_prefix_list,msg_dict =parse_config('BGP_PREFIX_SID.json')
    bgp_server_sock.bind((BGPADDR,BGPPORT))
    bgp_server_sock.listen(MAXCLIENTS)
    while True:
        client_sock = bgp_server_sock.accept()
        gevent.spawn(bgp_handler,client_sock,parsed_prefix_list,msg_dict)


if __name__ == '__main__':
    main()