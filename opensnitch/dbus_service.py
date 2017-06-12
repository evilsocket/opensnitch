from gi.repository import GLib

import dbus.mainloop.glib
import dbus.mainloop
import dbus.service
import dbus

import logging

from opensnitch.rule import RuleSaveOption, RuleVerdict


BUS_NAME = 'io.opensnitch.service'
OBJECT_PATH = '/'


class OpensnitchService(dbus.service.Object):

    def __init__(self, handlers, rules):
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

        bus = dbus.SessionBus()
        bus_name = dbus.service.BusName(BUS_NAME, bus=bus)

        self.handlers = handlers
        self._rules = rules

        super().__init__(bus_name, OBJECT_PATH)

    @dbus.service.signal(BUS_NAME, signature='usqssuss')
    def prompt(self, connection_id,
               hostname,
               dst_port,
               dst_addr,
               proto,
               app_pid,
               app_path,
               app_cmdline):
        # Signal is emitted by calling decorated function
        logging.debug('Prompting connection id %s', connection_id)

    @dbus.service.method(BUS_NAME, in_signature='iiib', out_signature='b')
    def connection_set_result(self, connection_id, save_option,
                              verdict, apply_to_all):
        save_option = int(save_option)
        verdict = int(verdict)
        apply_to_all = bool(apply_to_all)

        try:
            handler = self.handlers[int(connection_id)]
        except KeyError:
            return
        else:
            try:
                handler.future.set_result((save_option,
                                           verdict,
                                           apply_to_all))
            except Exception as e:
                logging.debug('Could not set result %s', e)

        if RuleSaveOption(save_option) != RuleSaveOption.ONCE:
            self._rules.add_rule(handler.conn, RuleVerdict(verdict),
                                 apply_to_all, save_option)

    @dbus.service.method(BUS_NAME,
                         in_signature='i', out_signature='b')
    def connection_recheck_verdict(self, connection_id):
        try:
            handler = self.handlers[int(connection_id)]
        except KeyError:
            # If connection is not found or verdict is set connection is
            # considered to be handled
            return True
        else:
            conn = handler.conn

        verd = self._rules.get_verdict(conn)
        if verd is None:
            return False

        handler.future.set_result((RuleSaveOption.ONCE,
                                   verd,
                                   False))  # Apply to all

        return True

    def run(self):
        loop = GLib.MainLoop()
        loop.run()
