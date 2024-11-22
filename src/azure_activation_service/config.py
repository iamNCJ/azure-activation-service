from pathlib import Path

# Base configuration directory
CONFIG_DIR = Path.home() / '.azure_activation_service'

# Cache file paths
ROLES_CACHE_FILE = CONFIG_DIR / 'roles_cache.json'

# Create config directory if it doesn't exist
CONFIG_DIR.mkdir(exist_ok=True)
