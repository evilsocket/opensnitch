
import os

_user_home = os.path.expanduser('~')
xdg_config_home = os.environ.get('XDG_CONFIG_HOME') or os.path.join(_user_home, '.config')
