from opensnitch.plugins import PluginBase, PluginSignal


class Sample(PluginBase):
    # fields overriden from parent class
    name = "Sample"
    version = 0
    author = "opensnitch"
    created = ""
    modified = ""
    enabled = False
    description = "OpenSnitch sample plugin"

    # where this plugin be executed.
    TYPE = [PluginBase.TYPE_POPUPS]

    def __init__(self):
        self.signal_in.connect(self.cb_signal)

    def configure(self):
        pass

    def load_conf(self):
        pass

    def compile(self):
        """Transform a json object to python objects.
        """
        print("Sample.compile()")

    def run(self, args):
        """Run the action on the given arguments.
        """
        print("Sample.run() args:", args)

    def cb_signal(self, signal):
        print("Plugin.signal received:", self.name, signal)
        try:
            if signal['signal'] == PluginSignal.ENABLE:
                self.enabled = True
        except Exception as e:
            print("Plugin.Sample.cb_signal() exception:", e)
