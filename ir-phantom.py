import sockstate
import argparse
import os
import time
import socket

parser = argparse.ArgumentParser()

parser.add_argument("host")
parser.add_argument("-p", "--port", help="Destination port", type=int, default=443)
args = parser.parse_args()

s = sockstate.Sock(remote=(args.host, args.port))
try:
    s.connect()

    s.send(os.urandom(32))
    time.sleep(0.001)
    s.send(os.urandom(8192))
    time.sleep(1)
    print(s, s.count_retransmits())
    s.printFlow()

except socket.timeout:
    print('%s 0 timeout' % (s))
except Exception as err:
    print(s, err)



sockstate.stop()
