# This is a copy of sd_core. config. load_config_toml but with some modifications
from sd_core.config import load_config_toml

default_config = """
[server]
host = "localhost"
port = "7600"
storage = "peewee"
cors_origins = "http://localhost:27180,http://localhost:3000,http://localhost:7600"

[server.custom_static]

[server-testing]
host = "localhost"
port = "5666"
storage = "peewee"
cors_origins = ""

[server-testing.custom_static]
""".strip()

config = load_config_toml("sd-server", default_config)