# This file is part of OpenSnitch.
#
# Copyright(c) 2017 Simone Margaritelli
# evilsocket@gmail.com
# http://www.evilsocket.net
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
from collections import defaultdict
import threading
import logging
import re


def writefile(path, value, mode="w"):
    with open(path, mode) as f:
        return f.write(value)


class ProcMon(threading.Thread):
    PROBE_NAME = "opensnitch_sys_execve"

    def __init__(self):
        threading.Thread.__init__(self)
        self.pids = defaultdict(dict)
        self.lock = threading.Lock()
        self.running = False
        self.daemon = True

    @staticmethod
    def enable():
        ProcMon.disable(False)
        logging.info("Enabling ProcMon ...")

        for d in ('sched_process_fork',
                  'sched_process_exec',
                  'sched_process_exit'):
            f = "/sys/kernel/debug/tracing/events/sched/%s/enable" % d
            writefile(f, "1")

        # Create the custom execve kprobe consumer
        # Command line args will be in %si, we're asking ftrace for them
        with open("/sys/kernel/debug/tracing/kprobe_events", "w") as f:
            f.write("p:kprobes/%s sys_execve" % (ProcMon.PROBE_NAME,))
            for i in range(1, 16):
                f.write(" arg%d=+0(+%d(%%si)):string" % (i, i*8))

        writefile("/sys/kernel/debug/tracing/events/kprobes/%s/enable" % ProcMon.PROBE_NAME, "1")  # noqa

    @staticmethod
    def disable(verbose=True):
        if verbose:
            logging.info("Disabling ProcMon ...")

        try:
            for d in ('sched_process_fork',
                      'sched_process_exec',
                      'sched_process_exit'):
                f = "/sys/kernel/debug/tracing/events/sched/%s/enable" % d
                writefile(f, "0")

            writefile("/sys/kernel/debug/tracing/events/kprobes/%s/enable" % ProcMon.PROBE_NAME, "0")  # noqa
            writefile("/sys/kernel/debug/tracing/kprobe_events", "-:%s" % ProcMon.PROBE_NAME, mode="a+")  # noqa
            writefile("/sys/kernel/debug/tracing/trace", "")
        except:
            pass

    @staticmethod
    def is_ftrace_available():
        try:
            with open("/proc/sys/kernel/ftrace_enabled", "rt") as fp:
                return fp.read().strip() == '1'
        except:
            pass

        return False

    def get_app(self, pid):
        return self.pids[pid] or None

    def _on_exec(self, pid, filename):
        with self.lock:
            p = self.pids[pid]
            p['filename'] = filename

        logging.debug("(pid=%d) %s %s",
                      pid,
                      filename,
                      p.get('args', ''))

    def _on_args(self, pid, args):
        with self.lock:
            self.pids[pid]['args'] = args

    def _on_exit(self, pid):
        try:
            del self.pids[pid]
        except KeyError:
            pass

    def run(self):
        logging.info("ProcMon running ...")
        self.running = True

        with open("/sys/kernel/debug/tracing/trace_pipe", 'rb') as pipe:
            PROBE_NAME = ProcMon.PROBE_NAME.encode()

            while True:
                try:
                    line = pipe.readline()

                    if PROBE_NAME in line:
                        m = re.search(b'^.*?\-(\d+)\s*\[', line)
                        if m is None:
                            continue

                        pid = int(m.group(1))
                        # "walk" over every argument field, 'fault' is our terminator.  # noqa
                        # If we see it it means that there are more cmdline args.  # noqa
                        if b'(fault)' in line:
                            line = line[:line.find(b'(fault)')]

                        args = b' '.join(
                            re.findall(b'arg\d+="(.*?)"', line))

                        self._on_args(pid, args.decode())

                    else:
                        m = re.search(b'sched_process_(.*?):', line)
                        if m is None:
                            continue

                        event = m.group(1)
                        if event == b'exec':
                            filename = re.search(
                                b'filename=(.*?)\s+pid=', line).group(1)
                            pid = int(
                                re.search(b'\spid=(\d+)', line).group(1))

                            self._on_exec(pid, filename.decode())

                        elif event == b'exit':
                            mm = re.search(
                                b'\scomm=(.*?)\s+pid=(\d+)', line)
                            # command = mm.group(1)
                            pid = int(mm.group(2))

                            self._on_exit(pid)

                except Exception as e:
                    logging.warning(e)
