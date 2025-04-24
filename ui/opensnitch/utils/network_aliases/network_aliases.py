#   Copyright (C) 2024      Nolan Carouge
#
#   This file is part of OpenSnitch.
#
#   OpenSnitch is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   OpenSnitch is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with OpenSnitch.  If not, see <http://www.gnu.org/licenses/>.

import json
import ipaddress
import os

class NetworkAliases:
    ALIASES = {}

    @staticmethod
    def load_aliases():
        # Define the path to the network_aliases.json file
        script_dir = os.path.dirname(os.path.abspath(__file__))
        filename = os.path.join(script_dir, 'network_aliases.json')

        # Check if the file exists before attempting to load it
        if not os.path.exists(filename):
            raise FileNotFoundError(f"The file '{filename}' does not exist.")

        # Load the JSON file
        with open(filename, 'r') as f:
            NetworkAliases.ALIASES = json.load(f)
        print(f"Loaded network aliases from {filename}")  # Confirmation message

    @staticmethod
    def get_alias(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            for alias, networks in NetworkAliases.ALIASES.items():
                for network in networks:
                    net_obj = ipaddress.ip_network(network)
                    if ip_obj in net_obj:
                        return alias
        except ValueError:
            pass
        return None

    @staticmethod
    def get_networks_for_alias(alias):
        return NetworkAliases.ALIASES.get(alias, [])

    @staticmethod
    def get_alias_all():
        # Return a list of all alias names
        return list(NetworkAliases.ALIASES.keys())

# Load aliases at startup
try:
    NetworkAliases.load_aliases()
except FileNotFoundError as e:
    print(e)
