import traceback
import logging
from logging.handlers import RotatingFileHandler
import os.path

from opensnitch.utils.xdg import xdg_config_home

# https://docs.python.org/3/library/logging.html#logging-levels
TRACE = 5

def new(tag, max_bytes=5242880, max_backup=5, filename=None):
    formatter = logging.Formatter('%(asctime)s - [%(levelname)s][%(filename)s:%(funcName)s:%(lineno)d] %(message)s')
    logger = logging.getLogger(tag)
    if filename is not None and filename != "":
        fh = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=max_backup)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    else:
        ch = logging.StreamHandler()
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    logger.setLevel(logging.WARNING)

    return logger

def get(tag):
    if tag is None or tag == "":
        tag = "opensnitch"
    # getLogger() always return the same logger object
    return logging.getLogger(tag)

def print_stack():
    for line in traceback.format_stack():
        print(line.strip())
