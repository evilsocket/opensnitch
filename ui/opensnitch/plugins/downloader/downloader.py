import os
import logging
import requests
import threading
from queue import Queue

from opensnitch.version import version
from opensnitch.dialogs.stats import StatsDialog
from opensnitch.notifications import DesktopNotifications
from opensnitch.plugins import PluginBase, PluginSignal
from opensnitch.utils.xdg import xdg_config_home
from opensnitch.utils import GenericTimer

ch = logging.StreamHandler()
#ch.setLevel(logging.ERROR)
formatter = logging.Formatter('%(asctime)s - %(name)s - [%(levelname)s] %(message)s')
ch.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(ch)
logger.setLevel(logging.WARNING)

class Downloader(PluginBase):
    """A plugin that schedules downloads from remote urls.

    This plugin may require to create a rule to allow connections to the
    configured urls, to avoid popups.
    """
    # fields overriden from parent class
    name = "Downloader"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    enabled = False
    description = "Download remote resources to local directories"

    # default
    TYPE = [PluginBase.TYPE_GLOBAL]

    # list of scheduled tasks
    scheduled_tasks = {}
    default_conf = "{0}/{1}".format(xdg_config_home, "/opensnitch/actions/downloaders.json")

    def __init__(self, config=None):
        self.signal_in.connect(self.cb_signal)
        self._config = config
        self._desktop_notifications = DesktopNotifications()
        self._ok_msg = ""
        self._err_msg = ""
        self._notify_title = "[OpenSnitch] Blocklist downloader"
        self._resultsQueue = Queue()
        self._app_icon = os.path.join(os.path.abspath(os.path.dirname(__file__)), "../../res/icon-white.svg")

    def configure(self, parent=None):
        # TODO:
        if type(parent) == StatsDialog:
            pass
            #_gui.add_panel_section()

    def compile(self):
        """Transform a json object to python objects.
        """
        logger.debug("compile()")
        try:
            if self._config.get('config') == None:
                logger.warning("compile() config:[] missing")
                return

            settings = self._config['config']
            for idx, config in enumerate(settings):
                for url in config['urls']:
                    if url['localfile'] == "" or url['remote'] == "" or config['name'] == "":
                        logger.debug("compile() downloader name, url, localfile, units and interval fields cannot be empty")
                        continue

                self._notify = config.get('notify')
                if self._notify != None:
                    ok = self._notify.get('success')
                    err = self._notify.get('error')
                    if ok != None:
                        ok_msg = ok.get('desktop')
                        if ok_msg:
                            self._ok_msg = ok_msg
                    if err != None:
                        err_msg = err.get('desktop')
                        if err_msg:
                            self._err_msg = err_msg

                if config['units'] == 'seconds':
                    interval = float(config['interval'])
                elif config['units'] == 'minutes':
                    interval = float(config['interval']) * 60
                elif config['units'] == 'hours':
                    interval = (float(config['interval']) * 60) * 60
                elif config['units'] == 'days':
                    interval = ((float(config['interval']) * 60) * 60) * 60
                else:
                    logger.warning("compile() unknown time format '{0}'".format(config['units']))

                self.scheduled_tasks[config['name']] = self.new_timer(interval, config)
        except Exception as e:
            logger.warning("compile() exception:", extra=e)

    def run(self, parent=None, args=()):
        """Run the action on the given arguments.
        """
        if parent == StatsDialog:
            pass

        settings = self._config['config']
        for idx, config in enumerate(settings):
            self.scheduled_tasks[config['name']].start()

    def new_timer(self, interval, config):
        logger.debug("new_timer()")
        t = GenericTimer(interval, True, self.cb_run_tasks, (self.scheduled_tasks, config,))
        return t

    def cb_run_tasks(self, args):
        try:
            tasks, config = args
            updated = True
            failed_urls = []
            threads = []
            for url in config['urls']:
                if not url['enabled']:
                    logger.debug("cb_run_tasks() disabled -> %s", url['remote'])
                    continue

                # TODO:
                #  - check and save content-length header, to avoid unnecessary
                #  downloads.
                #  - cancel on too many failures
                #  - on slow connections/too much urls + refresh interval too
                #  low, timers may overlap.
                #
                #response = requests.head(url['remote'])
                #print("Downloaders >> {0} >> length >> {1}".format(url, response.headers['content-length']))
                th = threading.Thread(
                        target=self.download_url,
                        args=(config['name'], url['remote'], url['localfile'],)
                    )
                th.start()
                threads.append(th)

            for th in threads:
                th.join()

            while not self._resultsQueue.empty():
                remote, ok = self._resultsQueue.get_nowait()
                updated &= ok
                if not ok:
                    failed_urls.append(remote)

            result_msg = self._ok_msg if updated else self._err_msg
            result_msg = "{0}\n\n{1}".format(result_msg, failed_urls if len(failed_urls) > 0 else "")
            if self._notify != None:
                if self._desktop_notifications.is_available() and self._desktop_notifications.are_enabled():
                    self._desktop_notifications.show(
                        self._notify_title,
                        result_msg,
                        self._app_icon
                    )
                else:
                    logger.debug("notification module is not available or disabled.")

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

    def download_url(self, task_name, remote, localfile):
        logger.debug("download_url() %s -> %s", remote, localfile)

        try:
            response = requests.get(
                remote,
                # introduced in v0.12.0 (2012)
                # XXX: support prefetch= ?
                stream=True,
                headers={'User-Agent': 'OpenSnitch v%s' % version}
            )
            if response.status_code != 200:
                logger.debug("download_url() error: %s", task_name)
                self._resultsQueue.put((remote, False))
                return False

            with open(localfile, "wb") as f:
                # write content in chunks, to avoid excessive mem usage.
                for chunk in response.iter_content(1024):
                    if not chunk:
                        break
                    f.write(chunk)

        except Exception as e:
            logger.debug("download_url() exception: %s", repr(e))
            self._resultsQueue.put((remote, False))
            return False

        self._resultsQueue.put((remote, True))
        return True
