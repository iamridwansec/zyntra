"""Centralized portable filesystem paths for Zyntra."""

import os
from pathlib import Path


# Application resources
PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "config"

SUBDOMAIN_WORDLIST = CONFIG_DIR / "wordlists" / "subdomains.txt"
VHOST_WORDLIST = PROJECT_ROOT / "data" / "wordlists" / "vhosts.txt"


def get_user_data_dir() -> Path:
    """
    Resolve Zyntra's persistent data directory.

    Portable storage beside the application is the default.
    ZYNTRA_DATA_DIR allows an explicit alternative location.
    """
    custom_directory = os.environ.get("ZYNTRA_DATA_DIR")

    if custom_directory:
        return Path(custom_directory).expanduser().resolve()

    return PROJECT_ROOT / "data"


# Persistent data stored on the portable drive by default
USER_DATA_DIR = get_user_data_dir()
ASSESSMENT_COUNTER_FILE = USER_DATA_DIR / "assessment_counter.txt"
ASSESSMENTS_DIR = USER_DATA_DIR / "assessments"
