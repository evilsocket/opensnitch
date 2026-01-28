import json
import logging
import threading
import re
from datetime import datetime
from queue import Queue
import requests

from PyQt6.QtCore import QCoreApplication as QC
from PyQt6.QtSql import QSqlQuery

from opensnitch.customwidgets.generictableview import GenericTableModel
from opensnitch.plugins.virustotal import _utils

ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.DEBUG)

classA_net = r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
classB_net = r'172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]+\.\d{1,3}\.\d{1,3}'
classC_net = r'192\.168\.\d{1,3}\.\d{1,3}'
others_net = r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}'
multiIPv4 = r'2[32][23459]\.\d{1,3}\.\d{1,3}\.\d{1,3}'
multiIPv6 = r'ffx[0123458ef]::'
LAN_RANGES = "^(" + others_net + "|" + classC_net + "|" + classB_net + "|" + classA_net + "|" + multiIPv4 + "|" + multiIPv6 + "|::1|f[cde].*::.*)$"

hostsDelegateConfig = {
    "name": "hostsDelegateConfig",
    "created": "",
    "updated": "",
    "actions": {
        "highlight": {
            "enabled": True,
            "cells": [
                {
                    "text": ["harmless"],
                    "cols": [2],
                    "color": "green",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": ["suspicious"],
                    "cols": [2],
                    "color": "orange",
                    "bgcolor": "",
                    "alignment": ["center"]
                }
            ],
            "rows": [
                {
                    "text": ["malicious"],
                    "cols": [2],
                    "color": "red",
                    "bgcolor": "",
                    "alignment": []
                }
            ]
        }
    }
}


class VTTableModel(GenericTableModel):

    def __init__(self,
                 tableName,
                 headerLabels,
                 api_url,
                 api_key,
                 api_timeout,
                 api_quota,
                 realtime):
        super().__init__(tableName, headerLabels)

        self.api_url = api_url
        self.api_key = api_key
        self.api_timeout = api_timeout
        self.api_quota = api_quota
        self.realtime = realtime

        self.cols_num = 0
        self.reconfigureColumns()
        self.resultsQueue = Queue()
        self.lan_regex = re.compile(LAN_RANGES)
        self.results_cache = {}
        self.ip_resolving = []
        self.api_queries = 0

    def reconfigureColumns(self):
        self.headerLabels = []
        self.setHorizontalHeaderLabels(self.headerLabels)
        self.headerLabels.append(QC.translate("stats", "What", ""))
        self.headerLabels.append(QC.translate("stats", "Hits", ""))
        self.headerLabels.append("Consensus")
        self.headerLabels.append("Category")
        self.headerLabels.append("DNS records")
        self.headerLabels.append("SSL info")

        self.cols_num = len(self.headerLabels)

        # https://docs.virustotal.com/reference/domains-object
        # possible columns:
        # DNS records
        # - last_dns_records.value, .rname,
        # SSL CA, issuer, domains
        # - last_https_certificate.subject_alternative_name
        # - last_https_certificate.issuer.C , .CN, .O
        # - last_https_certificate.subject.C , .CN, .L, .O, .ST
        # - last_https_certificate.subject.C , .CN, .L, .O, .ST
        # - registrar
        # - whois

        self.setHorizontalHeaderLabels(self.headerLabels)
        self.setColumnCount(len(self.headerLabels))
        self.lastColumnCount = len(self.headerLabels)

    def lastQuery(self):
        return self.origQueryStr

    def update_col_count(self):
        queryColumns = self.realQuery.record().count()
        if queryColumns < self.cols_num:
            self.reconfigureColumns()
        else:
            # update view's columns
            if queryColumns != self.lastColumnCount:
                self.setModelColumns(queryColumns)

    def fillVisibleRows(self, q, upperBound, force=False):
        super().fillVisibleRows(q, upperBound, force)

        if self.columnCount() < self.cols_num or self.realtime is False:
            return

        for n, col in enumerate(self.items):
            try:
                self.get_info(n, col[0])
            except Exception as e:
                logger.debug("ip2location.fillVisibleRows exception() %s", repr(e))
            finally:
                self.items[n] = col
        self.lastItems = self.items

    def resolve_all(self):
        for n, col in enumerate(self.items):
            self.get_info(n, col[0])

    def quota_exceeded(self):
        return self.api_queries > self.api_quota

    def reset_cells(self, pos):
        for c in range(2, self.cols_num):
            self.items[pos][c] = ""

    def set_cells_info(self, pos, info):
        try:
            verdict = info['data']['attributes']['last_analysis_stats']
            cats = info['data']['attributes']['categories']
            last_dns_records = info['data']['attributes']['last_dns_records']
            ssl_certificate = info['data']['attributes']['last_https_certificate']

            self.items[pos][2] = _utils.get_verdict(verdict)
            self.items[pos][3] = _utils.get_categories(cats)
            self.items[pos][4] = _utils.get_dns_records(last_dns_records)
            self.items[pos][5] = _utils.get_ssl_info(ssl_certificate)
        except Exception as e:
            logger.debug("set_cells_info() exception: %s", repr(e))
            self.reset_cells(pos)

    def get_info(self, pos, ip):
        if ip in self.results_cache:
            last_seen = self.results_cache[ip]['last_seen']
            diff = datetime.now() - last_seen
            if diff.days == 0:
                info = self.results_cache[ip]['info']
                if info is None:
                    return
                self.set_cells_info(pos, info)
                return

        if self.lan_regex.match(ip) is not None:
            if self.items[pos][0] != ip:
                return
            self.reset_cells(pos)
            return
        if ip in self.ip_resolving:
            return
        if self.quota_exceeded():
            logger.debug("api quota exceeded (%d/%d)", self.api_queries, self.api_quota)
            return

        th = threading.Thread(
                target=self.cb_ip_info,
                args=(pos, ip,)
            )
        th.start()
        self.ip_resolving.append(ip)
        self.api_queries += 1

        while not self.resultsQueue.empty():
            result = self.resultsQueue.get_nowait()
            rip = result['ip']
            rpos = result['pos']
            info = result['info']

            if rip in self.ip_resolving:
                self.ip_resolving.remove(rip)

            self.results_cache[rip] = {'info': info, 'last_seen': datetime.now()}
            if result['info'] is None:
                if self.items[rpos][0] != rip:
                    return
                self.reset_cells(rpos)
                return

            col = self.items[rpos]
            if col[0] == rip:
                self.set_cells_info(rpos, info)

    def cb_ip_info(self, pos, what):
        logger.debug("get_info() pos: %d what: %s", pos, what)

        result = {'ip': what, 'pos': pos, 'info': None}
        try:
            response = requests.get(
                #f"https://localhost/?ip={ip}",
                self.api_url+what,
                timeout=self.api_timeout,
                stream=True,
                headers={
                    'x-apikey': self.api_key,
                }
            )
            if response.status_code != 200:
                logger.debug("get_info() %s, error %s: %s", what, response.status_code, response.content)
                self.resultsQueue.put(result)
                #self.resultsQueue.put(json.loads('{"country_name": "shit", "as": "aa"}'))
                return False

            info = json.loads(response.content)
            result['info'] = info
            self.resultsQueue.put(result)

        except Exception as e:
            logger.debug("get_info() %s exception: %s", what, repr(e))
            #self.resultsQueue.put(json.loads('{"country_name": "shit", "as": "aa"}'))
            self.resultsQueue.put(result)
            return False

        return True
