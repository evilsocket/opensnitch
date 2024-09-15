import logging
import requests
import json
import re

from PyQt5 import QtCore
from opensnitch.version import version
from opensnitch.config import Config
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.dialogs.prompt import PromptDialog
from opensnitch.dialogs.processdetails import ProcessDetailsDialog
from opensnitch.plugins.virustotal import _popups
from opensnitch.plugins.virustotal import _procdialog

ch = logging.StreamHandler()
#ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)

class VTSignals(QtCore.QObject):
    completed = QtCore.pyqtSignal(object, object, object, object, object)
    error = QtCore.pyqtSignal(str, object, object, str, object)

class VTAnalysis(QtCore.QRunnable):
    def __init__(self, parent, config, what, url, timeout, api_key, conn):
        super(VTAnalysis, self).__init__()
        #QtCore.QThread.__init__(self)
        self.signals = VTSignals()
        self.parent = parent
        self.config = config
        self.what = what
        self.url = url
        self.timeout = timeout
        self.api_key = api_key
        self.conn = conn

    def run(self):
        self.analyze(self.parent, self.config, self.what, self.url, self.timeout, self.api_key, self.conn)

    def analyze(self, parent, conf, what, url, timeout, api_key, conn):
        """Returns analyze results on success.
        None on error.
        """
        logger.debug("vt_analysis.analyze() %s, %s, %s", url, what, type(parent))
        response={}
        try:
            # >= v2.13. Not tested with < v2.13
            response = requests.get(
                url,
                timeout=timeout,
                headers={'x-apikey': api_key, 'User-Agent': 'OpenSnitch v%s' % version}
            )
            self.signals.completed.emit(what, parent, conf, conn, response)
        except Exception as e:
            logger.warning("vt_analysis.analyze() exception: %s", repr(e))
            self.signals.error.emit(what, parent, conf, "Exception: {0}".format(e), response)

class Virustotal(PluginBase):
    """
    Analyzes properties of a connection: domain, IP, file hash.
    json format:
        {
            "config": {
              "api_timeout": 2,
              "api_key": "123456",
              "api_domains_url": "https://www.virustotal.com/api/v3/domains/",
              "api_ips_url": "https://www.virustotal.com/api/v3/ip_addresses/",
              "api_files_url": "https://www.virustotal.com/api/v3/files/"
            },
            "check": ["domains", "ips", "files"]
        }

    The config item is optional, and will override default configuration if specified.

    Documentation:
     - get an API key: https://virustotal.readme.io/docs/please-give-me-an-api-key
     - https://developers.virustotal.com/reference/domain-info
     - https://developers.virustotal.com/reference/domains-1
     - https://developers.virustotal.com/reference/ip-info
     - https://developers.virustotal.com/reference/file-info


     Privacy warning: remember that the domains, ips or hashes will be sent to a remote
    """
    # Friendly reminder: this is just a PoC, an example of what can be done.

    # XXX ideas:
    # - Send a desktop notification if something is detected as malicious.
    # - [DONE] Add a tab page to the popup with the result of the analysis.
    #   * Add a link to know more about the domain, certificates, etc.
    # - Change the icon if malicious.
    # - Hook Procs tab list, get the hash of each binary, upload to VT and
    # update the list with info.
    # - From the process dialog, allow to upload the binary, and obtain the process
    # analysis and behaviour.
    #   * [DONE] added tab with info about the process
    # - Add a button to upload a file for analysis.
    # - Periodically scan all domains/IPs visited.
    #   * from procs/hosts/ips -> on demand.
    #   * as soon as we add a domain to the DB?

    # TODO: similar services
    # urlhaus-api.abuse.ch
    #
    # analysis with yara rules: yaraify-api.abuse.ch
    # curl -X POST -d '{ "query": "lookup_hash", "search_term": "38e1c0ca15ed83ed27148c31a31e0b33de627519ab2929d4aa69484534589086" '} https://yaraify-api.abuse.ch/api/v1/

    # malware domain test: malware.wicar.org

    name = "Virustotal"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    #enabled = False
    description = "Analyze domains and IPs with VirusTotal"

    # where this plugin is allowed
    # could be applied on list of connections, process dialog, etc
    TYPE = [PluginBase.TYPE_POPUPS]

    # result of the query
    QUERY_OK = 0
    QUERY_ERROR = 1

    # verdict of the analysis
    VERDICT_UNKNOWN = 0
    VERDICT_BENIGN = 1
    VERDICT_MALICIOUS = 2

    ANALYZING_MESSAGE = "\u231B Virustotal: analyzing ..."
    VERDICT_BENIGN_MESSAGE = "\u2714 Virustotal"
    VERDICT_MALICIOUS_MESSAGE = "\u26A0  Virustotal warning"

    # Virustotal returns the analysis of many engines (> 70)
    # Sometimes only 1 analysis returns malicious, which may lead to false
    # positives.

    # consider the object (domain, ip, etc) malicious if the number of reports
    # is equal or above this threshold.
    MALICIOUS_THRESHOLD = 1
    WARNING_THRESHOLD = 5
    # There's also a community reputation:
    # reputation: <integer> domain's score calculated from the votes of the
    # VirusTotal's community.

    API_DOMAINS = "https://www.virustotal.com/api/v3/domains/"
    API_IPS = "https://www.virustotal.com/api/v3/ip_addresses/"
    #sha256, sha1 or md5
    API_FILES = "https://www.virustotal.com/api/v3/files/"

    API_EXCEEDED = False
    API_KEY = 'https://virustotal.readme.io/docs/please-give-me-an-api-key'
    API_CONNECT_TIMEOUT = 1

    # urls to view the details of an object
    RESULTS_DOMAINS = "https://www.virustotal.com/gui/domain/"
    RESULTS_IPS = "https://www.virustotal.com/gui/ip-address/"

    CHECK_DOMAINS = "domains"
    CHECK_IPS = "ips"
    CHECK_FILES_HASHES = "hashes"
    # TODO
    # CHECK_PROC_BEHAVIOUR = "behaviour"

    classA_net = r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    classB_net = r'172\.1[6-9]\.\d+\.\d+|172\.2[0-9]\.\d+\.\d+|172\.3[0-1]+\.\d{1,3}\.\d{1,3}'
    classC_net = r'192\.168\.\d{1,3}\.\d{1,3}'
    others_net = r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3}'
    multiIPv4 = r'2[32][23459]\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    multiIPv6 = r'ffx[0123458ef]::'
    MULTICAST_RANGE = "^(" + multiIPv4 + ")$"
    LAN_RANGES = "^(" + others_net + "|" + classC_net + "|" + classB_net + "|" + classA_net + multiIPv4 + "|" + multiIPv6 + "|::1|f[cde].*::.*)$"

    def __init__(self, config=None):
        self.API_DOMAINS = "https://www.virustotal.com/api/v3/domains/"
        self.API_IPS = "https://www.virustotal.com/api/v3/ip_addresses/"
        #sha256, sha1 or md5
        self.API_FILES = "https://www.virustotal.com/api/v3/files/"

        self.API_EXCEEDED = False
        self.API_KEY = ''
        self.API_CONNECT_TIMEOUT = 1

        self.MALICIOUS_THRESHOLD = 1
        self.WARNING_THRESHOLD = 5

        # original json config received
        self._config = config
        self.ip_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        self.lan_regex = re.compile(Virustotal.LAN_RANGES)
        self.signal_in.connect(self.cb_incoming_events)
        self.threadsPool = QtCore.QThreadPool()

    def configure(self, parent=None):
        """add widgets to all supported areas of the GUI"""

        if type(parent) == PromptDialog:
            vt_tab = _popups.build_vt_tab(self, parent)
            _popups.add_vt_tab(parent, vt_tab)

        elif type(parent) == ProcessDetailsDialog:
            vt_tab = _procdialog.build_vt_tab(self, parent)
            _procdialog.add_vt_tab(self, parent, vt_tab)

    def compile(self):
        """Transform json items to python objects, if needed.
        It's executed only once.
        """
        logger.debug("compile()")
        for idx in self._config:
            if idx == "config" and 'api_timeout' in self._config[idx]:
                self.API_CONNECT_TIMEOUT = self._config[idx]['api_timeout']
            if idx == "config" and 'api_key' in self._config[idx]:
                self.API_KEY = self._config[idx]['api_key']
            if idx == "config" and 'api_domains_url' in self._config[idx]:
                self.API_DOMAINS = self._config[idx]['api_domains_url']
            if idx == "config" and 'api_ips_url' in self._config[idx]:
                self.API_IPS = self._config[idx]['api_ips_url']
            if idx == "config" and 'api_files_url' in self._config[idx]:
                self.API_FILES = self._config[idx]['api_files_url']

        if self._config.get("malicious-label-style") == None:
            self._config['malicious-label-style'] = 'red'
        if self._config.get("benign-label-style") == None:
            self._config['benign-label-style'] = 'green'
        if self._config.get("malicious-message") == None:
            self._config['malicious-message'] = self.VERDICT_MALICIOUS_MESSAGE
        if self._config.get("benign-message") == None:
            self._config['benign-message'] = self.VERDICT_BENIGN_MESSAGE

    def run(self, parent, args):
        """
        arg0 - object: parent object,
        arg1 - list: connection,

        Pre-requisites: create a rule to allow outbound connections to
        www.virustotal.com on port 443 (from your uid).
        """
        # parent == PromptDialog
        self.parent = parent

        try:
            if type(parent) == PromptDialog:
                parent.messageLabel.linkActivated.connect(lambda link: _popups._cb_popup_link_clicked(link, parent))
                _popups.reset_widgets_state(parent)
                #_popups.add_analyzing_msg(self, parent)
                conn = args[0]
                if 'www.virustotal.com' == conn.dst_host:
                    return
                if self.lan_regex.match(conn.dst_host) != None or self.lan_regex.match(conn.dst_ip) != None:
                    return

                logger.debug("analyzing %s, %s", self.API_DOMAINS, conn.dst_host)

                # parse config file "virustotal": {}
                url = ""
                for what in self._config['check']:
                    if Virustotal.CHECK_DOMAINS == what:
                        if conn.dst_host == "" or conn.dst_ip == conn.dst_host:
                            continue
                        url = self.API_DOMAINS + conn.dst_host
                    elif Virustotal.CHECK_IPS == what:
                        url = self.API_IPS + conn.dst_ip
                    elif Virustotal.CHECK_FILES_HASHES == what:
                        checksum = conn.process_checksums[Config.OPERAND_PROCESS_HASH_MD5]
                        if checksum != "":
                            url = self.API_FILES + checksum
                        else:
                            logger.debug("run() checksum of this process empty, skipping")
                            continue
                    else:
                        logger.info("run() unknown target: %s", what)
                        continue

                    logger.debug("run() analyzing: %s", url)

                    vt_thread = VTAnalysis(parent, self._config, what, url, self.API_CONNECT_TIMEOUT, self.API_KEY, conn)
                    vt_thread.signals.completed.connect(self.analysis_completed)
                    vt_thread.signals.error.connect(self.analysis_error)
                    self.threadsPool.start(vt_thread)

            else:
                print("Virustotal error: parent type not supported:", type(parent))
        except Exception as e:
            logger.warning("run() exception: %s", repr(e))
        #finally:
        #    if type(parent) == PromptDialog:
        #        parent.stackedWidget.removeWidget(vt_tab)

    def analysis_error(self, what, parent, conf, error, response):
        logger.warning("analysis_error(): %s, %s, %s", what, error, repr(response))
        if type(parent) == PromptDialog:
            self.update_popup(what, response, parent, conf, error)

    def analysis_completed(self, what, parent, conf, conn, response):
        try:
            self.API_EXCEEDED = (response.status_code == 403 or response.status_code == 204)
            if self.API_EXCEEDED:
                logger.info("analysis_completed() API USAGE EXCEEDED")
                return

            if type(parent) == PromptDialog:
                self.update_popup(what, response, parent, conf)
            elif type(parent) == ProcessDetailsDialog:
                _procdialog.update_tab(what, response, parent, conf, conn)
            else:
                print("[virustotal] analysis_completed() parent object type not supported:", type(parent))

        except Exception as e:
            logger.warning("analysis_completed() exception: %s", repr(e))
            return

    def update_popup(self, what, response, parent, config, errmsg=None):
        """Update pop-up widgets based on the results of the analysis.
        """
        # XXX: use PromptDialog methods to update widgets
        # set_app_description()
        # set_app_path() <- allow to colorize text
        # etc.

        error = (errmsg != None)
        malicious = False
        labelStyle = "color: {0}".format(config['benign-label-style'])
        try:
            if error:
                if response and response.content == 401:
                    raise ValueError("Unauthorized (401).\nCheck the validity of the Virustotal API key.\n\n{0}".format(errmsg))
                else:
                    raise ValueError(errmsg)
            #if response.get('content') == None:
            #    raise Exception("Invalid response from server?")

            result = json.loads(response.content)
            # checksums API returns 404 if the hash is not in the DB.
            # XXX: result of this query could be marked as 'unknown' instead of
            # 'benign'.
            if result.get('data') == None:
                logger.debug("update_popup() no data? %s, %s", what, response)
                if Virustotal.CHECK_FILES_HASHES == what:
                    return

            verdict = result['data']['attributes']['last_analysis_stats']
            #print("[Virustotal] RESULT:\n", conn.dst_host, "\n", result['data']['attributes']['last_analysis_stats'])

            # XXX: if we analyze multiple objects (domains, ips, hashes...),
            # onlye the last response is stored.
            _popups.add_vt_response(parent, result)

            malicious = self.is_malicious(verdict['malicious'])

            # self.set_malicious(parent)
        except ValueError as e:
            logger.warning("update_popup() value error: %s -> %s", repr(e), response)
            error = True
            _popups.add_vt_response(parent, None, e)
        except Exception as e:
            logger.warning("update_popup() exception: %s -> %s", repr(e), response)
            error = True
            _popups.add_vt_response(parent, None, "Exception: {0}".format(repr(e)))

        finally:
            message = "<font color=\"{0}\">{1} ({2})</font><br>{3}".format(
                config['benign-label-style'],
                config['benign-message'],
                what,
                parent.messageLabel.text()
            )
            if malicious:
                labelStyle = "color: {0}".format(config['malicious-label-style'])
                message = "<font color=\"{0}\">{1} ({2}, flagged by {3} sources)</font> <a href='#virustotal-warning'>(Details)</a><br>{4}".format(
                    config['malicious-label-style'],
                    config['malicious-message'],
                    what,
                    verdict['malicious'],
                    parent.messageLabel.text()
                )
                parent.messageLabel.setStyleSheet(labelStyle)
            if error:
                labelStyle = "color: darkOrange"
                message = "<font color=\"darkOrange\">Virustotal ({0}): analysis error</font> <a href='#virustotal-warning'>(Details)</a><br>{1}".format(
                    what,
                    parent.messageLabel.text()
                )
                parent.messageLabel.setStyleSheet(labelStyle)


            parent.messageLabel.setText(message)

            if Virustotal.CHECK_DOMAINS == what:
                parent.messageLabel.setStyleSheet(labelStyle)
            if Virustotal.CHECK_IPS == what:
                parent.destIPLabel.setStyleSheet(labelStyle)
            if Virustotal.CHECK_FILES_HASHES == what:
                parent.checksumLabel.setStyleSheet(labelStyle)

    def is_benign(self, mal_results):
        return mal_results < self.MALICIOUS_THRESHOLD

    def is_malicious(self, mal_results):
        return mal_results >= self.MALICIOUS_THRESHOLD

    def cb_incoming_events(self, signal):
        """listens to events from parents (enable, configure, etc)
        """
        logger.debug("cb_incoming_events() %s", signal)
        try:
            if signal['signal'] == PluginSignal.ENABLE:
                self.enabled = True
            if signal['signal'] == PluginSignal.DISABLE:
                self.enabled = False
                #if not self.enabled:
                #    _popups.remove_vt_tab()
                #    _procdialog.remove_vt_tab()
        except Exception as e:
            logger.debug("cb_incoming_events() exception: %s", repr(e))
