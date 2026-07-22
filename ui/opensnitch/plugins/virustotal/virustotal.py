import json
import re
import logging
import requests

from PyQt6 import QtCore

from opensnitch.actions import Actions
from opensnitch.version import version
from opensnitch.config import Config
from opensnitch.utils import Icons
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.dialogs.events import StatsDialog, constants as evt_constants
from opensnitch.dialogs.prompt import PromptDialog, constants
from opensnitch.dialogs.processdetails import ProcessDetailsDialog
from opensnitch.plugins.virustotal import (
    _popups,
    _procdialog,
    _models,
    _utils
)
from opensnitch.customwidgets.colorizeddelegate import ColorizedDelegate

ch = logging.StreamHandler()
#ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)

class VTSignals(QtCore.QObject):
    completed = QtCore.pyqtSignal(object, object, object, object, object)
    error = QtCore.pyqtSignal(str, object, object, str, object, object)

class VTAnalysis(QtCore.QRunnable):
    def __init__(self, parent, config, what, url, timeout, api_key, conn):
        super(VTAnalysis, self).__init__()
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
            self.signals.error.emit(what, parent, conf, "Exception: {0}".format(e), conn, response)

class Virustotal(PluginBase):
    """Analyzes properties of a connection: domain, IP, file hash.
    json configuration example:
        {
            "loglevel": "debug",
            "config": {
              "api_timeout": 2,
              "api_key": "123456",
              "api_domains_url": "https://www.virustotal.com/api/v3/domains/",
              "api_ips_url": "https://www.virustotal.com/api/v3/ip_addresses/",
              "api_files_url": "https://www.virustotal.com/api/v3/files/"
            },
            "check": ["domains", "ips", "hashes"],
            "malicious": {
                "minimum-threshold": 1,
                "action": "reject",
                "icon": "dialog-warning"
                "use-community-score": false,
                "use-suspicious": false,
                "use-reputation": false
            },
            "widgets-colors": {
                "malicious": "blue",
                "benign": "green",
                "unknown": "darkOrange"
            },
            "exclusions": {
                "ips": ["127.", "192.168.", "1.1.1.1"],
                "domains": [".lan"]
            }
        }

    The config item is optional, and will override default configuration if specified.

    Documentation:
     - get an API key: https://virustotal.readme.io/docs/please-give-me-an-api-key
     - https://developers.virustotal.com/reference/domain-info
     - https://developers.virustotal.com/reference/domains-1
     - https://developers.virustotal.com/reference/ip-info
     - https://developers.virustotal.com/reference/file-info


     Privacy warning: remember that the domains, ips or hashes will be sent to a remote
     server.
    """
    # Friendly reminder: this is just a PoC, an example of what can be done.

    # XXX ideas:
    # - Send a desktop notification if something is detected as malicious.
    # - [DONE] Add a tab page to the popup with the result of the analysis.
    # - [DONE] Add a link to know more about the domain, certificates, etc.
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
    # Sometimes only 1 analysis returns malicious results, which may lead to false
    # positives.

    # consider the object (domain, ip, etc) malicious if the number of analyses
    # is equal or above this threshold.
    MALICIOUS_THRESHOLD = 1
    WARNING_THRESHOLD = 5
    # There's also a community reputation:
    # reputation: <integer> domain's score calculated from the votes of the
    # VirusTotal's community.
    # and community votes:
    # https://docs.virustotal.com/reference/ip-object#object-attributes

    VT_DOMAIN = "www.virustotal.com"
    API_DOMAINS = "https://www.virustotal.com/api/v3/domains/"
    API_IPS = "https://www.virustotal.com/api/v3/ip_addresses/"
    #sha256, sha1 or md5
    API_FILES = "https://www.virustotal.com/api/v3/files/"

    API_EXCEEDED = False
    API_KEY = 'https://virustotal.readme.io/docs/please-give-me-an-api-key'
    API_CONNECT_TIMEOUT = 1
    API_QUOTA = 500

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
    LAN_RANGES = "^(" + others_net + "|" + classC_net + "|" + classB_net + "|" + classA_net + "|" + multiIPv4 + "|" + multiIPv6 + "|::1|f[cde].*::.*)$"

    # options to colorize labels based on the results.
    # color values can be specified in hexadecimal or name:
    # https://doc.qt.io/qt-6/qcolorconstants.html#qt-colors
    widgets_colors = {
        'malicious': 'red',
        'benign': 'green',
        'unknown': 'orange'
    }

    # list of exclusions to avoid scanning/opening connections to VT.
    # it'll only check if something *contains* the exclusion. For example:
    #  dsthost: nas-server.lan
    #  exclusion: .lan
    #  if exclusion in dsthost -> exclude
    exclusions = {
        'ips': [],
        'domains': []
    }

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
        self.vt_model = None
        self.evt_dialog = None

    def configure(self, parent=None):
        """add widgets to all supported areas of the GUI"""

        if type(parent) == PromptDialog:
            vt_tab = _popups.build_vt_tab(self, parent)
            _popups.add_vt_tab(parent, vt_tab)
            parent.messageLabel.linkActivated.connect(lambda link: _popups._cb_popup_link_clicked(link, parent))

        elif type(parent) == ProcessDetailsDialog:
            vt_tab = _procdialog.build_vt_tab(self, parent)
            _procdialog.add_vt_tab(self, parent, vt_tab)

        elif type(parent) == StatsDialog:
            self.evt_dialog = parent
            view_config = self.evt_dialog.get_view_config(evt_constants.TAB_HOSTS)
            self.vt_model = _models.VTTableModel(
                view_config['name'],
                view_config['header_labels'],
                self.API_DOMAINS,
                self.API_KEY,
                self.API_CONNECT_TIMEOUT,
                self.API_QUOTA,
                True
            )

            view_config['view'] = self.evt_dialog.view_setup(
                self.evt_dialog.hostsTable,
                view_config['name'],
                model=self.vt_model,
                verticalScrollBar=self.evt_dialog.hostsScrollBar,
                resize_cols=(evt_constants.COL_WHAT,2),
                order_by=view_config['last_order_by'],
                limit=self.evt_dialog.get_view_limit()
            )
            _actions = Actions.instance()
            hostsDelegate = _actions.compile(_models.hostsDelegateConfig)
            view_config['view'].setItemDelegate(
                ColorizedDelegate(
                    view_config['view'],
                    actions=hostsDelegate
                )
            )
            #evt_dialog.set_view_config(evt_constants.TAB_HOSTS, view_config)


    def compile(self):
        """Transform json items to python objects, if needed.
        It's executed only once.
        """
        loglvl = self._config.get("loglevel")
        logger.setLevel(_utils.get_log_level(loglvl))

        logger.debug("compile()")
        for idx in self._config:
            if idx == "config" and 'api_timeout' in self._config[idx]:
                self.API_CONNECT_TIMEOUT = self._config[idx]['api_timeout']
            if idx == "config" and 'api_quota' in self._config[idx]:
                self.API_QUOTA = self._config[idx]['api_quota']
            if idx == "config" and 'api_key' in self._config[idx]:
                self.API_KEY = self._config[idx]['api_key']
            if idx == "config" and 'api_domains_url' in self._config[idx]:
                self.API_DOMAINS = self._config[idx]['api_domains_url']
            if idx == "config" and 'api_ips_url' in self._config[idx]:
                self.API_IPS = self._config[idx]['api_ips_url']
            if idx == "config" and 'api_files_url' in self._config[idx]:
                self.API_FILES = self._config[idx]['api_files_url']

        if self._config.get("exclusions") is not None:
            self.exclusions = self._config.get("exclusions")

        if self._config.get("widgets-colors") is not None:
            self.widgets_colors = self._config.get('widgets-colors')

        warnIcon = Icons.new(self, "dialog-warning")
        warnPix = warnIcon.pixmap(64, 64)
        if self._config.get("malicious") is None:
            self._config['malicious'] = {
                'action': "reject",
                'icon': warnIcon.pixmap(64, 64),
                'use-suspicious': False,
                'use-community-votes': False,
                'use-reputation': False,
                'minimum-threshold': self.MALICIOUS_THRESHOLD,
            }
        else:
            warnIcon = Icons.new(self, self._config['malicious']['icon'])
            self._config['malicious']['icon'] = warnIcon.pixmap(64, 64)

        self.MALICIOUS_THRESHOLD = self._config['malicious']["minimum-threshold"]

        if self._config.get("malicious-label-style") is None:
            self._config['malicious-label-style'] = 'red'
        if self._config.get("benign-label-style") is None:
            self._config['benign-label-style'] = 'green'
        if self._config.get("malicious-message") is None:
            self._config['malicious-message'] = self.VERDICT_MALICIOUS_MESSAGE
        if self._config.get("benign-message") is None:
            self._config['benign-message'] = self.VERDICT_BENIGN_MESSAGE

    def run(self, parent, args):
        """
        arg0 - object: parent object,
        arg1 - list: connection,

        Pre-requisites: create a rule to allow outbound connections to
        www.virustotal.com on port 443 from the GUI (from your uid).
        """
        # parent == PromptDialog
        self.parent = parent

        try:
            if type(parent) != PromptDialog:
                logger.debug("Virustotal error: parent type not supported: %s", type(parent))
                return

            _popups.reset_widgets_state(parent)
            #_popups.add_analyzing_msg(self, parent)
            conn = args[0]
            if conn.dst_host == Virustotal.VT_DOMAIN:
                return
            if self.lan_regex.match(conn.dst_host) is not None or self.lan_regex.match(conn.dst_ip) is not None:
                return
            for d in self.exclusions['domains']:
                  if d in conn.dst_host:
                    logger.debug(f"domain exclusion matched: {d} - {conn.dst_host}")
                    return
            for d in self.exclusions['ips']:
                  if d in conn.dst_ip:
                    logger.debug(f"ip exclusion matched: {d} - {conn.dst_ip}")
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
                    logger.info("run() unknown target, review the configuration: %s", what)
                    continue

                logger.debug("run() analyzing: %s", url)

                vt_thread = VTAnalysis(parent, self._config, what, url, self.API_CONNECT_TIMEOUT, self.API_KEY, conn)
                vt_thread.signals.completed.connect(self.analysis_completed)
                vt_thread.signals.error.connect(self.analysis_error)
                self.threadsPool.start(vt_thread)

        except Exception as e:
            logger.warning("run() exception: %s", repr(e))
        #finally:
        #    if type(parent) == PromptDialog:
        #        parent.stackedWidget.removeWidget(vt_tab)

    def analysis_error(self, what, parent, conf, error, conn, response):
        logger.warning("analysis_error(): %s, %s, %s", what, error, repr(response))
        if type(parent) == PromptDialog:
            self.update_popup(what, response, parent, conf, conn, error)

    def analysis_completed(self, what, parent, conf, conn, response):
        try:
            self.API_EXCEEDED = (response.status_code == 403 or response.status_code == 204)
            if self.API_EXCEEDED:
                logger.info("analysis_completed() API USAGE EXCEEDED")
                return

            if type(parent) == PromptDialog:
                self.update_popup(what, response, parent, conf, conn)
            elif type(parent) == ProcessDetailsDialog:
                _procdialog.update_tab(what, response, parent, conf, conn)
            else:
                logger.debug("[virustotal] analysis_completed() parent object type not supported: %s", type(parent))

        except Exception as e:
            logger.warning("analysis_completed() exception: %s", repr(e))

    def update_popup(self, what, response, parent, config, conn, errmsg=None):
        """Update pop-up widgets based on the results of the analysis.
        """
        # XXX: use PromptDialog methods to update widgets
        # set_app_description()
        # set_app_path() <- allow to colorize text
        # etc.

        error = (errmsg is not None)
        malicious = False
        labelStyle = "color: {0}".format(self.widgets_colors['benign'])
        try:
            if error:
                if response and response.content == 401:
                    raise ValueError("Unauthorized (401).\nCheck the validity of the Virustotal API key.\n\n{0}".format(errmsg))
                else:
                    raise ValueError(errmsg)
            #if response.get('content') is None:
            #    raise Exception("Invalid response from server?")

            result = json.loads(response.content)
            # checksums API returns 404 if the hash is not in the DB.
            # XXX: result of this query could be marked as 'unknown' instead of
            # 'benign'.
            if result.get('data') is None:
                logger.debug("update_popup() no data? %s, %s", what, response)
                if Virustotal.CHECK_FILES_HASHES == what:
                    return

            verdict = result['data']['attributes']['last_analysis_stats']
            votes = result['data']['attributes']['total_votes']
            reputation = result['data']['attributes']['reputation']
            #print("[Virustotal] RESULT:\n", conn.dst_host, "\n", result['data']['attributes']['last_analysis_stats'])

            # XXX: if we analyze multiple objects (domains, ips, hashes...),
            # only the last response is stored.
            _popups.add_vt_response(parent, result, conn)

            mal_num = verdict['malicious']
            susp_num = verdict['suspicious']
            mal_comm_votes = 0
            good_comm_votes = 0
            comm_votes = 0
            if config['malicious']['use-community-score']:
                mal_comm_votes = votes['malicious']
                good_comm_votes = votes['harmless']
                comm_votes = mal_comm_votes - good_comm_votes
                mal_num += comm_votes
            if config['malicious']['use-suspicious']:
                mal_num += susp_num
            if config['malicious']['use-reputation']:
                mal_num += -reputation
            malicious = self.is_malicious(mal_num)

            # self.set_malicious(parent)
        except ValueError as e:
            logger.warning("update_popup() value error: %s -> %s", repr(e), response)
            error = True
            _popups.add_vt_response(parent, None, conn ,e)
        except Exception as e:
            logger.warning("update_popup() exception: %s -> %s", repr(e), response)
            error = True
            _popups.add_vt_response(parent, None, conn, "Exception: {0}".format(repr(e)))

        finally:
            old_msg = parent.get_message_text()
            if what in old_msg:
                return
            message = "<font color=\"{0}\">{1} ({2})</font><br>{3}".format(
                self.widgets_colors['benign'],
                config['benign-message'],
                what,
                parent.get_message_text()
            )
            if malicious:
                if config['malicious'] is not None:
                    parent.set_default_action(Config.ACTION_REJECT_IDX)
                    parent.set_icon_pixmap(config['malicious']['icon'])

                labelStyle = "color: {0}".format(self.widgets_colors['malicious'])
                message = "<font color=\"{0}\">{1} ({2}, flagged by {3} sources, votes: {4})</font> <a href='#virustotal-warning'>(Details)</a><br>{5}".format(
                    self.widgets_colors['malicious'],
                    config['malicious-message'],
                    what,
                    mal_num,
                    comm_votes,
                    parent.get_message_text()
                )
                parent.set_message_style(labelStyle)
            if error:
                labelStyle = "color: {0}".format(self.widgets_colors['unknown'])
                message = "<font color=\"{0}\">Virustotal ({1}): analysis error</font> <a href='#virustotal-warning'>(Details)</a><br>{2}".format(
                    self.widgets_colors['unknown'],
                    what,
                    parent.get_message_text()
                )
                parent.set_message_style(labelStyle)


            parent.set_message_text(message)

            if Virustotal.CHECK_IPS == what:
                parent.destIPLabel.setStyleSheet(labelStyle)

            # skip setting checksum's or global labels style if there's a
            # warning about the checksum.
            if constants.WARNING_LABEL in parent.get_message_text():
                return

            if Virustotal.CHECK_DOMAINS == what:
                parent.set_message_style(labelStyle)
            if Virustotal.CHECK_FILES_HASHES == what:
                parent.checksumLabel.setStyleSheet(labelStyle)

    def is_benign(self, mal_results):
        return mal_results > self.MALICIOUS_THRESHOLD

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
