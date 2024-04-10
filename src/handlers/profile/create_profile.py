import json

from rich.console import Console
from os import makedirs, path
from uuid import uuid4

from handlers.profile.helper import BREADS_FOLDER

console = Console()

PROFILE_UUID = uuid4().hex


def initial_directory() -> None:
    """Create the initial breads directory (.breads/) on user $HOME"""

    if not path.exists(BREADS_FOLDER):
        makedirs(BREADS_FOLDER)
        console.print("[green][+][/] [bright_white].breads folder created in user home[/]")
        return True
    else:
        pass


def profile_folder(inp) -> None:
    """Create the profile folder with the name based on user input"""

    initial_directory()

    if len(inp) == 0:
        console.print("[red][!][/] [bright_white]You need to specify a profile name, use: [b]create_profile example[/][/]")
        return True

    global profile_name
    profile_name = inp

    console.print(f"[yellow][!][/] [bright_white]Creating [b]{profile_name}'s[/] profile folder [/]")
    folder_path = f"{BREADS_FOLDER}/{profile_name}"

    try:
        if not path.exists(folder_path):
            makedirs(folder_path)
            console.print(f"[green][+][/] [bright_white][b]{profile_name}[/] profile created. Load the profile with: [green]load_profile {profile_name}[/] [/]")

            initialize_profile_json()
        else:
            console.print(f"[red][!][/] [bright_white][b]{profile_name}[/] profile already exists\n [i]\_ Path: {folder_path}[/][/]")
            return True
    except Exception as error:
        console.print(f"[red][!][/] Error when creating profile folder: {error}[/]")
        return


def initialize_profile_json() -> None:
    """Create the base JSON file to be used by the profile to store the information collected"""

    profile_structure = {
        "profile_name": profile_name,
        "profile_uuid": PROFILE_UUID,
        "host": "",
        "username": "",
        "password": "",
        "domain": "",
    }

    json_path: str = f"{BREADS_FOLDER}/{profile_name}/settings.json"

    try:
        with open(json_path, "w", encoding="utf-8") as profile_json:
            json.dump(profile_structure, profile_json, ensure_ascii=False, indent=4)
            profile_json.truncate()

            console.print(f"    [italic bright_white]\_ Name: {profile_name} - UUID: {PROFILE_UUID} - Path: {json_path}[/]\n")

    except Exception as error:
        console.print(f"[red][!][/] [bright_white]Error creating profile json file: {error}[/]")
        return False
