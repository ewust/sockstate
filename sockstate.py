import socket
from scapy.all import *
import random
import threading
import time
import ssl

class PacketListener(object):

    def __init__(self):

        # Only listen on first instance
        if not hasattr(self, 'runListen'):
            self.conns = dict()  # flow (sip, sport, dip, dport) => Sock()
            self.runListen = True
            self.listenThread = threading.Thread(target=self.listen)
            self.listenThread.start()

    # Make a singleton, should only have one instance
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(PacketListener, cls).__new__(cls)
        return cls.instance

    # Given a Sock(), add its tuple
    def addConn(self, sock, bidi=True):
        flow = sock.getFlow()
        self.conns[flow] = sock

        if bidi:
            revflow = (flow[2], flow[3], flow[0], flow[1])
            self.conns[revflow] = sock

    def delConn(self, sock, bidi=True):
        flow = sock.getFlow()
        if flow in self.conns:
            del self.conns[flow]

        if bidi:
            revflow = (flow[2], flow[3], flow[0], flow[1])
            if revflow in self.conns:
                del self.conns[revflow]

    def handlePkt(self, pkt):
        # figure out what flow this is
        eth = Ether(pkt)
        if not(eth.haslayer(IP)):
            return
        ip = Ether(pkt).payload
        if not(ip.haslayer(TCP)):
            return
        tcp = ip.payload
        flow = (ip.src, tcp.sport, ip.dst, tcp.dport)
        if flow in self.conns:
            self.conns[flow].handlePkt(ip)

    def stop(self):
        self.runListen = False
        self.listenThread.join()

    def listen(self):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0x0300)
        while self.runListen:
            pkt = s.recv(0xffff)
            self.handlePkt(pkt)


def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]


class Sock(socket.socket):
    def __init__(self, remote=('127.0.0.1', 80), sport=None, sip=None, do_connect=False, timeout=1.1):

        if sport is None:
            sport = random.randint(1000,65000)
        if sip is None:
            sip = get_local_ip()

        self.packetListener = PacketListener()

        #self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        super().__init__(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.settimeout(timeout)
        self.bind((sip, sport))

        # Set our local flow
        self.sip, self.sport = self.getsockname()
        self.dip, self.dport = remote

        # keep track of packets
        self.pkts = []

        if do_connect:
            self.connect(remote)

    def connect(self, remote=None):
        # add the flow
        if remote is not None:
            self.dip, self.dport = remote
        self.packetListener.addConn(self)

        # connect
        super().connect((self.dip, self.dport))

    def send(self, data):
        return super().send(data)

    def recv(self, blen):
        return super().recv(blen)

    def close(self):
        return super().close()

    def getFlow(self):
        return (self.sip, self.sport, self.dip, self.dport)

    # assumes IP layer packets
    def handlePkt(self, pkt):
        self.pkts += pkt

    def printPkts(self):
        print('%s:%d -> %s:%d:' % (self.sip, self.sport, self.dip, self.dport))
        for pkt in self.pkts:
            print(pkt.__repr__())

    def printFlow(self):
        print('%s:%d -> %s:%d:' % (self.sip, self.sport, self.dip, self.dport))
        cli_isn = None
        srv_isn = None
        client = None
        for pkt in self.pkts:
            if cli_isn is None and pkt[TCP].flags == 'S':
                cli_isn = pkt[TCP].seq
                client = pkt[IP].src
            elif srv_isn is None and pkt[TCP].flags == 'SA':
                srv_isn = pkt[TCP].seq

            direction = '->' if pkt[IP].src == client else '  <-'
            data = ' +%d' % len(pkt[TCP].payload) if len(pkt[TCP].payload) > 0 else ''

            seq = pkt[TCP].seq
            ack = pkt[TCP].ack
            seq_diff = seq - cli_isn
            ack_diff = 0
            if srv_isn is not None:
                ack_diff = ack - srv_isn
            if pkt[IP].src != client:
                seq_diff = seq - srv_isn
                ack_diff = ack - cli_isn

            print('%s %s (%d, %d)%s' % (direction, pkt[TCP].flags, seq_diff, ack_diff, data))

    # Assumes that a retransmit has the same sequence as a previous (non-ACK) packet
    # This will miss overlaps / retransmits that are fragments, etc
    def count_retransmits(self):
        rex = 0
        data_seqs = set()
        for pkt in self.pkts:
            # ignore bare acks
            if pkt[TCP].flags == 'A':
                continue

            seq = pkt[TCP].seq
            if seq in data_seqs:
                rex += 1
            data_seqs.add(seq)
        return rex


    def has_handshake(self):
        state = 0 # wait-for-SYN, have SYN, have SYN_ACK, have ACK
        client = None
        for pkt in self.pkts:
            if state == 0 and pkt[TCP].flags == 'S':
                client = pkt[IP].src
                state = 1 # have SYN
            elif state == 1 and pkt[TCP].flags == 'SA' and pkt[IP].dst == client:
                state = 2 # have SYN_ACK
            elif state == 2 and pkt[TCP].flags == 'A' and pkt[IP].src == client:
                state = 3
                break

    return (state == 3)

    def __str__(self):
        return '%s:%d -> %s:%d (%d pkts)' % (self.sip, self.sport, self.dip, self.dport, len(self.pkts))

    def __del__(self):
        self.packetListener.delConn(self)



def stop():
    PacketListener().stop()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser()
    
    parser.add_argument("host")
    parser.add_argument("-p", "--port", help="Destination port", type=int, default=443)
    parser.add_argument("-s", "--sni", help="SNI of the host", default="example.com")
    args = parser.parse_args()
    
    
    # Experiment 1:
    # Connect to server, verify that it connects (SYN, SYN-ACK, ACK)
    s = Sock(remote=(args.host, args.port))
    try:
        s.connect()
    except Exception as err:
        print(err)
    #s.printFlow()
    #print(has_handshake(s.pkts))
    
    
    # Experiment 2:
    # Send 32 bytes, see if we retransmit
    s.send(b'a'*32)
    
    time.sleep(1)
    
    s.printFlow()
    print('Handshake: %s, Retransmits: %d' % (s.has_handshake(), s.count_retransmits()))
    
    
    print('-------')
    # Experiment 3:
    # Talk TLS
    s = Sock(remote=(args.host, args.port))
    try:
        s.connect()
    except Exception as err:
        print(err)
    
    hostname = args.sni
    context = ssl.create_default_context()
    with context.wrap_socket(s, server_hostname=hostname) as ssock:
        print('TLS version: ', ssock.version)
    
    s.printFlow()
    print('Handshake: %s, Retransmits: %d' % (s.has_handshake(), s.count_retransmits()))
    
    
    
    
    # Stop capturing
    PacketListener().stop()
