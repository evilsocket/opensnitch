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
import select
import re
from collections import defaultdict
import os
import threading
import logging

def writefile(path, value, mode="w"):
    with open(path, mode) as f:
        return f.write(value)

class ProcMon(threading.Thread):
    PROBE_NAME = "opensnitch_sys_execve"

    def __init__(self):
        threading.Thread.__init__(self)
        self.pids    = defaultdict(dict)
        self.lock    = threading.Lock()
        self.running = False
        self.daemon  = True

    @staticmethod
    def enable():
        ProcMon.disable(False)
        logging.info( "Enabling ProcMon ..." )

        writefile("/sys/kernel/debug/tracing/events/sched/sched_process_fork/enable", "1")
        writefile("/sys/kernel/debug/tracing/events/sched/sched_process_exec/enable", "1")
        writefile("/sys/kernel/debug/tracing/events/sched/sched_process_exit/enable", "1")

        # Create the custom execve kprobe consumer
        with open("/sys/kernel/debug/tracing/kprobe_events", "w") as f:
            f.write("p:kprobes/%s sys_execve" % (ProcMon.PROBE_NAME,))
            #Command line args will be in %si, we're asking ftrace to give them to us
            for i in range(1, 16):
                f.write(" arg%d=+0(+%d(%%si)):string" % (i, i*8))

        writefile("/sys/kernel/debug/tracing/events/kprobes/%s/enable" % (ProcMon.PROBE_NAME,), "1")

    @staticmethod
    def disable(verbose=True):
        if verbose:
            logging.info( "Disabling ProcMon ..." )

        try:
            writefile("/sys/kernel/debug/tracing/events/sched/sched_process_fork/enable", "0")
            writefile("/sys/kernel/debug/tracing/events/sched/sched_process_exec/enable", "0")
            writefile("/sys/kernel/debug/tracing/events/sched/sched_process_exit/enable", "0")
            writefile("/sys/kernel/debug/tracing/events/kprobes/%s/enable" % (ProcMon.PROBE_NAME,), "0")
            writefile("/sys/kernel/debug/tracing/kprobe_events", "-:%s" % (ProcMon.PROBE_NAME,), mode = "a+")
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

    def get_app_name( self, pid ):
        if pid is not None:
            pid = int(pid)
            with self.lock:
                if pid in self.pids and 'filename' in self.pids[pid]:
                    return self.pids[pid]['filename']

        return None

    def get_cmdline( self, pid ):
        pid = int(pid)
        with self.lock:
            if pid in self.pids and 'args' in self.pids[pid]:
                return self.pids[pid]['args']

        return None

    def _dump( self, pid, e ):
        logging.debug( "(pid=%d) %s %s" % ( pid, e['filename'], e['args'] if 'args' in e else '' ) )

    def _on_exec( self, pid, filename ):
        with self.lock:
            self.pids[pid]['filename'] = filename
            self._dump( pid, self.pids[pid] )

    def _on_args( self, pid, args ):
        with self.lock:
            self.pids[pid]['args'] = args

    def _on_exit( self, pid ):
        with self.lock:
            if pid in self.pids:
               del self.pids[pid]

    def run(self):
        logging.info( "ProcMon running ..." )
        self.running = True

        with open("/sys/kernel/debug/tracing/trace_pipe") as pipe:
            while True:
                try:
                    line = pipe.readline()

                    if ProcMon.PROBE_NAME in line:
                        m = re.search(r'^.*?\-(\d+)\s*\[', line)

                        if m is not None:
                            pid = int(m.group(1))
                            #"walk" over every argument field, 'fault' is our terminator.
                            # If we see it it means that there are more cmdline args.
                            if '(fault)' in line:
                                line = line[:line.find('(fault)')]

                            args = ' '.join(re.findall(r'arg\d+="(.*?)"', line))

                            self._on_args( pid, args )

                    else:
                        m = re.search(r'sched_process_(.*?):', line)
                        if m is not None:
                            event = m.group(1)

                            if event == 'exec':
                                filename = re.search(r'filename=(.*?)\s+pid=', line).group(1)
                                pid      = int(re.search(r'\spid=(\d+)', line).group(1))

                                self._on_exec( pid, filename )

                            elif event == 'exit':
                                mm = re.search(r'\scomm=(.*?)\s+pid=(\d+)', line)
                                command = mm.group(1)
                                pid = int(mm.group(2))

                                self._on_exit( pid )

                except Exception as e:
                    logging.warning(e)
