import logging
from logging.handlers import RotatingFileHandler
import os.path

from opensnitch.utils.xdg import xdg_config_home

def new(tag):
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - [%(filename)s:%(funcName)s:%(lineno)d][%(levelname)s] %(message)s')
    ch.setFormatter(formatter)
    logger = logging.getLogger(tag)
    logger.addHandler(ch)
    logger.setLevel(logging.WARNING)

    return logger

def new_file(tag, max_bytes=5242880, max_backup=5, filename=None):
    if filename is None:
        filename = os.path.join(xdg_config_home, 'opensnitch', 'ui.log')
    fh = RotatingFileHandler(filename, maxBytes=max_bytes, backupCount=max_backup)
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - [%(filename)s:%(funcName)s:%(lineno)d][%(levelname)s] %(message)s')
    ch.setFormatter(formatter)
    fh.setFormatter(formatter)
    logger = logging.getLogger(tag)
    logger.addHandler(fh)
    logger.addHandler(ch)
    logger.setLevel(logging.WARNING)

    return logger

def get(tag):
    if tag is None or tag == "":
        tag = "opensnitch"
    # getLogger() always return the same logger object
    return logging.getLogger(tag)
