import sockstate
import argparse
import os
import time

parser = argparse.ArgumentParser()

parser.add_argument("host")
parser.add_argument("-p", "--port", help="Destination port", type=int, default=443)
args = parser.parse_args()

s = sockstate.Sock(remote=(args.host, args.port))
try:
    s.connect()
except Exception as err:
    print(err)

s.send(os.urandom(32))
time.sleep(0.001)
s.send(os.urandom(8192))
print(s, s.count_retransmits())



sockstate.stop()
