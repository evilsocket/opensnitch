#!/usr/bin/python
import os
import sys
import logging

if not os.geteuid() == 0:
    sys.exit('OpenSnitch must be run as root.')

logging.basicConfig(format='[%(asctime)s] (%(levelname)s) %(message)s',level=logging.INFO)
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from opensnitch.snitch import Snitch

snitch = Snitch()

try:
    logging.info( "OpenSnitch running with pid %d." % os.getpid() )
    snitch.start()
except KeyboardInterrupt, e:
    pass

logging.info( "Quitting ..." )

snitch.stop()
