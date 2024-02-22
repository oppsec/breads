from rich import print
from os import mkdir, path
from uuid import uuid4

import json

from handlers.profile.helper import BREADS_FOLDER

PROFILE_UUID = uuid4().hex

def initial_directory() -> None:
    ''' Create the initial breads directory (.breads/) on user $HOME '''

    if not path.exists(BREADS_FOLDER):
        mkdir(BREADS_FOLDER)
        print("[green][+][/] [bright_white].breads folder created in user home[/]")
        return True
    else:
        pass

def profile_folder(inp) -> None:
    ''' Create the profile folder with the name based on user input '''

    if len(inp) == 0:
        print("[red][!][/] [bright_white]You need to specify a profile name, use: [b]create_profile example[/][/]")
        return True
    
    global profile_name
    profile_name = inp

    print(f"[green][+][/] [bright_white]Creating [b]{profile_name}'s[/] profile folder [/]")
    initial_directory()

    folder_path = f"{BREADS_FOLDER}/{profile_name}"

    if not path.exists(folder_path):
        mkdir(folder_path)
        print(f"[green][+][/] [bright_white][b]{profile_name}[/] profile created[/]")
        initialize_profile_json()
    else:
        print(f"[red][!][/] [bright_white][b]{profile_name}[/] profile already exists\n [i]\_ Path: {folder_path}[/][/]")
        return True
    
def initialize_profile_json() -> None:
    ''' Create the base JSON file to be used by the profile to store the information collected '''

    profile_structure = {
        "profile_name": profile_name,
        "profile_uuid": PROFILE_UUID,
        "host": "",
        "username": "",
        "password": ""
    }

    json_path: str = f"{BREADS_FOLDER}/{profile_name}/settings.json"

    try:
        with open(json_path, 'w') as profile_json:
            json.dump(profile_structure, json_path, ensure_ascii=False, indent=4)
            profile_json.truncate()

            print(f"[yellow][!][/] [bright_white][i]\_ Profile name: {profile_name} - UUID: {PROFILE_UUID} - Path: {json_path}[/][/]")

    except Exception as error:
        print(f"[red][!][/] [bright_white]Error when trying to create the base profile JSON file: {error}[/]")
        return False