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
