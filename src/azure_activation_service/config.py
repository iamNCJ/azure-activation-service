import os
from pathlib import Path

# Base configuration directory
azure_config = Path(os.getenv('AZURE_CONFIG_DIR', str(Path.home() / '.azure')))
CONFIG_DIR = azure_config.parent / '.azure_activation_service'

# Cache file paths
ROLES_CACHE_FILE = CONFIG_DIR / 'roles_cache.json'

# Auto activate config
AUTO_ACTIVATE_CONFIG = CONFIG_DIR / 'auto_activate.json'
DEFAULT_IMPORT_CONFIG_FILE = azure_config.parent / 'pim.json'

# Create config directory if it doesn't exist
CONFIG_DIR.mkdir(exist_ok=True)
