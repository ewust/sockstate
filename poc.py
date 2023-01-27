import socket
from scapy.all import *
import random
import threading
import time

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



class Sock(object):
    def __init__(self, remote=('127.0.0.1', 80), sport=None, sip=None, do_connect=True):

        if sport is None:
            sport = random.randint(1000,65000)
        if sip is None:
            sip = get_local_ip()

        self.packetListener = PacketListener()

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        self.s.bind((sip, sport))

        # Set our local flow
        self.sip, self.sport = self.s.getsockname()
        self.dip, self.dport = remote

        # keep track of packets
        self.pkts = []

        if do_connect:
            self.connect(remote)

    def connect(self, remote):
        # add the flow
        self.packetListener.addConn(self)

        # connect
        self.s.connect(remote)

    def send(self, data):
        return self.s.send(data)

    def recv(self, blen):
        return self.s.recv(blen)

    def close(self):
        return self.s.close()

    def getFlow(self):
        return (self.sip, self.sport, self.dip, self.dport)

    # assumes IP layer packets
    def handlePkt(self, pkt):
        self.pkts += pkt

    def printFlow(self):
        print('%s:%d -> %s:%d:' % (self.sip, self.sport, self.dip, self.dport))
        for pkt in self.pkts:
            print(pkt.__repr__())

    def __del__(self):
        self.packetListener.delConn(self)


def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]




s = Sock(remote=('54.174.72.166', 443), do_connect=True)


#s.send('Hello world')


s2 = Sock(remote=('54.174.72.166', 443), do_connect=True)

s.send(b'Hello world')

time.sleep(1)

print('---')
s.printFlow()

PacketListener().stop()
