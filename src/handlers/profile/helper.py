from pathlib import Path
from os import environ

def get_user_home() -> None:
    ''' Return user home directory '''

    return str(Path.home())

BREADS_FOLDER = f"{get_user_home()}/.breads"

def get_current_profile() -> None:
    ''' Get current user profile name based on environment variables (breads_profile) '''

    profile = environ.get("breads_profile") if environ.get("breads_profile", "None") else ""
    return str(profile)