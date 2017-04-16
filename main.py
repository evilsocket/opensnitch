#!/usr/bin/python

from opensnitch.packetqueue import PacketQueue

q = PacketQueue()

print "Running ..."

try:
    q.start()
except KeyboardInterrupt, e:
    pass

print "\n\nStopping ..."

q.stop()
