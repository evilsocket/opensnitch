
# common configuration to Highlight Action column
commonDelegateConfig = {
    "name": "commonDelegateConfig",
    "created": "",
    "updated": "",
    "actions": {
        "highlight": {
            "enabled": True,
            "cells": [
                {
                    "text": ["allow", "\u2713 online"],
                    "operator": "==",
                    "cols": [1, 2, 3],
                    "color": "green",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": ["deny", "\u2613 offline"],
                    "cols": [1, 2, 3],
                    "color": "red",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": ["reject"],
                    "cols": [1, 2, 3],
                    "color": "purple",
                    "bgcolor": "",
                    "alignment": ["center"]
                }
            ],
            "rows": []
        }
    }
}

# firewall rules configuration to Highlight Enabled and Action columns
fwDelegateConfig = {
    "name": "defaultFWDelegateConfig",
    "created": "",
    "updated": "",
    "actions": {
        "highlight": {
            "enabled": True,
            "cells": [
                {
                    "text": [
                        "allow",
                        "True",
                        "accept",
                        "jump",
                        "masquerade",
                        "snat",
                        "dnat",
                        "tproxy",
                        "queue",
                        "redirect",
                        "True",
                        "ACCEPT"

                    ],
                    "cols": [7, 10],
                    "color": "green",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": [
                        "deny",
                        "False",
                        "drop",
                        "DROP",
                        "stop"
                    ],
                    "cols": [7, 10],
                    "color": "red",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": [
                        "reject",
                        "return"
                    ],
                    "cols": [7, 10],
                    "color": "purple",
                    "bgcolor": "",
                    "alignment": ["center"]
                }

            ],
            "rows": []
    }
  }
}

# rules configuration to Highlight Enabled and Action columns
rulesDelegateConfig = {
    "name": "defaultRulesDelegateConfig",
    "created": "",
    "updated": "",
    "actions": {
        "highlight": {
            "enabled": True,
            "cells": [
                {
                    "text": ["allow", "True"],
                    "cols": [3, 4],
                    "color": "green",
                    "bgcolor": "",
                    "alignment": ["center"]
                    },
                    {
                    "text": ["deny", "False"],
                    "cols": [3, 4],
                    "color": "red",
                    "bgcolor": "",
                    "alignment": ["center"]
                    },
                    {
                    "text": ["reject"],
                    "cols": [3, 4],
                    "color": "purple",
                    "bgcolor": "",
                    "alignment": ["center"]
                    }
            ],
            "rows": []
        }
    }
}

netstatDelegateConfig = {
    "name": "netstatDelegateConfig",
    "created": "",
    "updated": "",
    "actions": {
        "highlight": {
            "enabled": True,
            "cells": [
                {
                    "text": ["LISTEN"],
                    "cols": [1],
                    "color": "green",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": ["CLOSE"],
                    "cols": [1],
                    "color": "red",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": ["Established"],
                    "cols": [1],
                    "color": "blue",
                    "bgcolor": "",
                    "alignment": ["center"]
                },
                {
                    "text": [
                        "TCP_SYN_SENT", "TCP_SYN_RECV",
                        "TCP_FIN_WAIT1", "TCP_FIN_WAIT2",
                        "TCP_TIME_WAIT", "TCP_CLOSE_WAIT",
                        "TCP_LAST_ACK", "TCP_CLOSING",
                        "TCP_NEW_SYNC_RECV"
                    ],
                    "cols": [1],
                    "color": "",
                    "bgcolor": "",
                    "alignment": ["center"]
                }
            ],
            "rows": []
        }
    }
}
