
import glob
import json
import os.path


class Profiles():

    @staticmethod
    def load_predefined_profiles():
        profiles = glob.glob("/etc/opensnitchd/system-fw.d/profiles/*.profile")
        p = []
        for pr_path in profiles:
            with open(pr_path) as f:
                p.append({os.path.basename(pr_path): json.load(f)})

        return p


class ProfileAcceptOutput():
    value = {
        "Name": "accept-mangle-output",
        "Table": "mangle",
        "Family": "inet",
        "Priority": "",
        "Type": "mangle",
        "Hook": "output",
        "Policy": "accept",
        "Rules": [
        ]
    }


class ProfileDropOutput():
    value = {
        "Name": "drop-mangle-output",
        "Table": "mangle",
        "Family": "inet",
        "Priority": "",
        "Type": "mangle",
        "Hook": "output",
        "Policy": "drop",
        "Rules": [
        ]
    }


class ProfileAcceptForward():
    value = {
        "Name": "accept-mangle-forward",
        "Table": "mangle",
        "Family": "inet",
        "Priority": "",
        "Type": "mangle",
        "Hook": "forward",
        "Policy": "accept",
        "Rules": [
        ]
    }


class ProfileDropForward():
    value = {
        "Name": "drop-mangle-forward",
        "Table": "mangle",
        "Family": "inet",
        "Priority": "",
        "Type": "mangle",
        "Hook": "forward",
        "Policy": "drop",
        "Rules": [
        ]
    }


class ProfileAcceptInput():
    value = {
        "Name": "accept-filter-input",
        "Table": "filter",
        "Family": "inet",
        "Priority": "",
        "Type": "filter",
        "Hook": "input",
        "Policy": "accept",
        "Rules": [
        ]
    }


class ProfileDropInput():
    """
    Set input filter table policy to DROP and add the needed rules to allow
    outbound connections.
    """

    # TODO: delete dropInput profile's rules
    value = {
        "Name": "drop-filter-input",
        "Table": "filter",
        "Family": "inet",
        "Priority": "",
        "Type": "filter",
        "Hook": "input",
        "Policy": "drop",
        "Rules": [
            {
                "Table": "",
                "Chain": "",
                "UUID": "profile-drop-inbound-2d7e6fe4-c21d-11ec-99a6-3c970e298b0c",
                "Enabled": True,
                "Position": "0",
                "Description": "[profile-drop-inbound] allow localhost connections",
                "Parameters": "",
                "Expressions": [
                    {
                        "Statement": {
                            "Op": "",
                            "Name": "iifname",
                            "Values": [
                                {
                                    "Key": "lo",
                                    "Value": ""
                                }
                            ]
                        }
                    }
                ],
                "Target": "accept",
                "TargetParameters": ""
            },
            {
                "Enabled": True,
                "Description": "[profile-drop-inbound] allow established,related connections",
                "UUID": "profile-drop-inbound-e1fc1a1c-c21c-11ec-9a2a-3c970e298b0c",
                "Expressions": [
                    {
                        "Statement": {
                            "Op": "",
                            "Name": "ct",
                            "Values": [
                                {
                                    "Key": "state",
                                    "Value": "related"
                                },
                                {
                                    "Key": "state",
                                    "Value": "established"
                                }
                            ]
                        }
                    }
                ],
                "Target": "accept",
                "TargetParameters": ""
            }
        ]
    }
