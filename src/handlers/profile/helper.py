from pathlib import Path
from os import environ
from json import load, JSONDecodeError
from rich.console import Console
console = Console

def get_user_home() -> str:
    """ Return user's home directory path as string """

    return str(Path.home())

BREADS_FOLDER = f"{get_user_home()}/.breads"

def get_current_profile() -> str:
    """ Read breads_profile environment variable value and return as string """

    profile = environ.get("breads_profile") if environ.get("breads_profile", "None") else ""
    return str(profile)

def get_current_profile_path() -> str:
    """ Return a string from current profile path """
    
    return str(BREADS_FOLDER + '/' + get_current_profile())

def load_profile_settings(self):
    """ Get username, password and domain from profile setting.json file """

    if get_current_profile() == 'None':
        console.print("[red][!][/] You need to load a profile first, use 'load_profile' command")
        return False
        
    settings_json_file = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"

    try:
        with open(settings_json_file, 'r') as settings_file:
            data = load(settings_file)

            username = data.get('username')
            username = username.split('\\', 1)
            username = username[-1]
            password = data.get('password')
            domain = data.get('domain')

            return username, password, domain
    except FileNotFoundError:
        console.print("[red][!][/] Could not find the settings file.")
        return False
    except JSONDecodeError:
        console.print("[red][!][/] Invalid JSON format in settings file.")
        return False