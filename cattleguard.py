from json import dump, load
from pathlib import Path
from re import search

from zenlib.logging import loggify

from tpm_wrapper import createprimary, evictcontrol, get_handles, getrandom, nvread

DEFAULT_CONFIG = {"seal_pcrs": [0, 7], "primary_hierarchy": "owner", "parent_auth": None, "primary_auth": "password"}


@loggify
class CattleGuard:
    """CattleGuard uses the TPM to seal LUKS key data"""

    def __init__(self, config_file="/etc/cattleguard/cattleguard.json"):
        self.config_file = Path(config_file)
        if not self.config_file.is_file():
            self.create_config()
        else:
            self.load_config()
        self.logger.debug(f"Checking TPM by reading random data: {bytes(getrandom(32))}")
        self.handles = get_handles()
        if self.handles:
            self.logger.info("Found TPM handles: %s" % self.handles)
        self.map_data = {}

    def create_config(self):
        """Create the default json config file"""
        self.config = DEFAULT_CONFIG
        self.logger.debug("Default config: %s" % self.config)
        self.logger.info("Writing default config to file: %s" % self.config_file)
        with open(self.config_file, "w") as file:
            dump(self.config, file)

    def load_config(self):
        """Reads the json config file"""
        self.logger.info("Loading config from file: %s" % self.config_file)
        with open(self.config_file, "r") as file:
            self.config = load(file)

        for key in DEFAULT_CONFIG:
            if key not in self.config:
                self.logger.warning("Key not found in config: %s" % key)
                self.logger.info("[%s] Adding default value to config: %s" % (key, DEFAULT_CONFIG[key]))
                self.config[key] = DEFAULT_CONFIG[key]

    def init_primary(self):
        """Initializes the primary key"""
        key_context, rsa = createprimary(self.config["primary_hierarchy"], self.config["parent_auth"])
        self.logger.info("Created primary key with rsa: %s" % rsa)

        if input("Do you want to save the primary key context? [y/N]: ").lower() == "y":
            print(evictcontrol(key_context, self.config["primary_hierarchy"], self.config["parent_auth"]))

    def read_map(self, handle):
        """Reads the seal map from the TPM"""
        map_data = nvread(handle)
        for entry in ["priv", "pub"]:
            if entry_data := search(rb"%s=([0-9a-fA-F]{7})" % entry.encode(), map_data):
                self.logger.debug("[%s] Read handle location: %s" % (entry, entry_data.group(1)))
                self.map_data[entry] = entry_data.group(1).decode()
            else:
                raise ValueError("Handle not found in map data: %s" % entry)

        self.logger.info("Got map data: %s" % self.map_data)
