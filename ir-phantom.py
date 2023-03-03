import sockstate
import argparse
import os
import time
import socket
from scapy.all import *

parser = argparse.ArgumentParser()

parser.add_argument("host")
parser.add_argument("-p", "--port", help="Destination port", type=int, default=443)
parser.add_argument("-v", "--verbose", help="Print all packets", action='store_true')
args = parser.parse_args()

def has_empty_psh_ack(s):
    # Check for an empty PSH-ACK (injection)
    client = None
    for pkt in s.pkts:
        if client is None and pkt[TCP].flags == 'S':
            client = pkt[IP].src
        is_client = (pkt[IP].src == client)
        if is_client:
            continue
        pl = pkt[TCP].payload
        #print(pkt[TCP].flags, len(pl), type(pl) is not Padding)
        if pkt[TCP].flags == 'PA' and (len(pl) == 0 or type(pl) is Padding):
            return True
    return False


def get_ack_rtt(s):
    client = None
    first_data_t = None
    first_data_expect_ack = None
    for t,pkt in zip(s.times, s.pkts):
        #print(pkt)
        if client is None and pkt[TCP].flags == 'S':
            client = pkt[IP].src
        pl = pkt[TCP].payload
        if pkt[IP].src == client and (len(pl)>0 and type(pl) is not Padding) and first_data_t is None:
            first_data_t = t
            #first_data_expect_ack = pkt[TCP].seq + len(pl)
            first_data_expect_ack = pkt[TCP].seq+1 # anything larger is fine
            #print('First data, expecting ack %d' % first_data_expect_ack)
        if first_data_t is not None and (pkt[IP].dst == client) and (pkt[TCP].flags == 'A' or pkt[TCP].flags == 'PA') and pkt[TCP].ack >=  first_data_expect_ack:
            return (t - first_data_t)
            
    return None



s = sockstate.Sock(remote=(args.host, args.port))
try:
    time.sleep(0.5)
    s.connect()

    s.send(os.urandom(32))
    time.sleep(0.001)
    s.send(os.urandom(1000))
    time.sleep(0.001)
    s.send(os.urandom(1000))
    time.sleep(0.001)
    s.send(os.urandom(1000))
    time.sleep(1)
    hs_rtt = s.get_hs_rtt()
    d_rtt = get_ack_rtt(s)
    if hs_rtt is None:
        hs_rtt = -1
    if d_rtt is None:
        d_rtt = -1
    print('%s %d retx, %s hs_rtt %.3fms, data_rtt %.3fms' % (s, s.count_retransmits(), 'injected' if has_empty_psh_ack(s) else '', hs_rtt*1000, d_rtt*1000))
    if args.verbose:
        s.printFlow()

except socket.timeout:
    print('%s 0 timeout' % (s))



sockstate.stop()
