import os
import os.path
import logging
import requests
import json
import threading
from queue import Queue
from PyQt6.QtCore import QCoreApplication as QC

from opensnitch.version import version
from opensnitch.dialogs.stats import StatsDialog
from opensnitch.notifications import DesktopNotifications
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.utils.xdg import xdg_config_home
from opensnitch.utils import GenericTimer

ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
#logger.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)

class Versionchecker(PluginBase):
    """A plugin that checks periodically OpenSnitch available release.

    This plugin may require to create a rule to allow connections to the
    configured urls, to avoid popups.
    """
    # fields overriden from parent class
    name = "Versionchecker"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    enabled = False
    description = "Check for latest release version"
    # https://docs.github.com/en/rest/releases/releases?apiVersion=2022-11-28
    github_api_version = "2022-11-28"
    github_api_url = "https://api.github.com/repos/evilsocket/opensnitch/releases"
    default_config = {
        'enabled': False,
        'config': {
            'check_on_start': True,
            'name': 'checker',
            'interval': "12",
            'units': "hours",
            'url': github_api_url
        }
    }

    # default
    TYPE = [PluginBase.TYPE_GLOBAL]

    # list of scheduled tasks
    scheduled_tasks = {}
    default_conf = "{0}/{1}".format(xdg_config_home, "/opensnitch/actions/versioncheckers.json")

    def __init__(self, config=None):
        self.signal_in.connect(self.cb_signal)
        self._config = config
        self._desktop_notifications = DesktopNotifications()
        self._ok_msg = ""
        self._err_msg = ""
        self._notify_title = "[OpenSnitch] Version checker"
        self._resultsQueue = Queue()
        self._app_icon = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../res/icon-white.svg")
        # XXX: we assume that github releases are called vX.Y.Z,
        # which in the future may be not the case.
        self._version = "v"+version

    def configure(self, parent=None):
        if type(parent) == StatsDialog:
            pass

    def compile(self):
        """Transform a json object to python objects.
        """
        logger.debug("compile()")
        try:
            if self._config.get('config') == None:
                logger.warning("compile() config:[] missing, using default config")
                config = self.default_config['config']
            else:
                config = self._config.get('config')

            interval = 0
            if config['units'] == 'seconds':
                interval = float(config['interval'])
            elif config['units'] == 'minutes':
                interval = float(config['interval']) * 60
            elif config['units'] == 'hours':
                interval = (float(config['interval']) * 60) * 60
            elif config['units'] == 'days':
                interval = ((float(config['interval']) * 60) * 60) * 60
            elif config['units'] == "":
                logger.debug("compile() interval checker disabled")
                return
            else:
                logger.warning("compile() unknown time format '{0}'".format(config['units']))
                return

            self.scheduled_tasks[config['name']] = self.new_timer(interval, config)
        except Exception as e:
            logger.warning("compile() exception:", extra=e)

    def run(self, parent=None, args=()):
        """Run the action on the given arguments.
        """
        if parent == StatsDialog:
            pass

        try:
            settings = self._config['config']
            # this option requires to have a rule to allow connections from the
            # GUI. Otherwise the GUI will be blocked until the request
            # finishes.
            if settings['check_on_start']:
                self.cb_run_tasks((self.scheduled_tasks, settings,))
            self.scheduled_tasks[settings['name']].start()
        except Exception as e:
            logger.warning("run() exception:", extra=e)

    def new_timer(self, interval, config):
        logger.debug("new_timer()")
        t = GenericTimer(interval, True, self.cb_run_tasks, (self.scheduled_tasks, config,))
        return t

    def cb_run_tasks(self, args):
        try:
            tasks, config = args
            last_version = ""
            if config['url'] == "":
                logger.debug("cb_run_tasks(): url parametr must not be empty")
                return

            th = threading.Thread(
                    target=self.check_version,
                    args=(config['name'], config['url'],)
                )
            th.start()
            th.join()

            while not self._resultsQueue.empty():
                last_version = self._resultsQueue.get_nowait()

            #if Utils.check_versions(request.stats.daemon_version):
            result_msg = QC.translate("stats", "Version {0} is available".format(version))
            if last_version != self._version:
                if self._desktop_notifications.is_available() and self._desktop_notifications.are_enabled():
                    self._desktop_notifications.show(
                        self._notify_title,
                        result_msg,
                        self._app_icon
                    )
                else:
                    logger.debug("notification module is not available or is disabled.")

        except Exception as e:
            logger.warning("cb_run_tasks.exception: %s", repr(e))

    def cb_signal(self, signal):
        logger.debug("cb_signal: %s, %s", self.name, signal)
        try:
            if signal == PluginSignal.ENABLE:
                self.enabled = True

            if signal['signal'] == PluginSignal.DISABLE or signal['signal'] == PluginSignal.STOP:
                for t in self.scheduled_tasks:
                    logger.debug("cb_signal.stopping task: %s, %s", self.name, signal)
                    self.scheduled_tasks[t].stop()

        except Exception as e:
            logger.warning("cb_signal() exception: %s", repr(e))

    def check_version(self, task_name, remote):
        logger.debug("check_version() %s", remote)

        try:
            response = requests.get(
                "https://api.github.com/repos/evilsocket/opensnitch/releases",
                stream=True,
                headers={
                    'User-Agent': 'OpenSnitch v%s' % version,
                    'Accept': 'application/vnd.github+json',
                    'X-GitHub-Api-Version': self.github_api_version
                }
            )
            if response.status_code != 200:
                logger.debug("check_version() error: %s", task_name)
                self._resultsQueue.put("")
                return False

            releases = json.loads(response.content)
            latest = releases[0]['name']
            if latest != version:
                self._resultsQueue.put(latest)

        except Exception as e:
            logger.debug("check_version() exception: %s", repr(e))
            self._resultsQueue.put("")
            return False

        return True
