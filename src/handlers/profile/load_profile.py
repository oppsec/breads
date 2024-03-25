from rich.prompt import Prompt
from rich.console import Console
from pathlib import Path
from os import environ
from uuid import uuid4

from handlers.profile.helper import BREADS_FOLDER

import json

BREADS_FOLDER = Path(BREADS_FOLDER)
PROFILE_UUID = uuid4().hex
console = Console()

def list_profiles():
    ''' List profiles found on $USER/.breads/ '''

    if not BREADS_FOLDER.exists():
        console.print("[red][!][/] .breads directory not found. Initialize one with 'create_profile' command\n")
        return []

    folders = [folder for folder in BREADS_FOLDER.iterdir() if folder.is_dir()]
    if not folders:
        console.print("[red][!][/] No profiles found in .breads directory. Create one with 'create_profile' command\n")
    else:
        for folder in folders:
            console.print(f"[cyan]* {folder.name}[/]")
    return folders

def get_profile_settings_path(profile_name):
    ''' Get settings.json from profile '''
    return BREADS_FOLDER / profile_name / "settings.json"

def load_profile(profile_name):
    ''' Load specified profile based on user input '''
    settings_path = get_profile_settings_path(profile_name)

    with settings_path.open('r+') as json_file:
            existing_data = json.load(json_file)

            host = existing_data['host']
            username = existing_data['username']
            password = existing_data['password']
            domain = existing_data['domain']

            if not host:
                console.print("[green][+][/] [bright_white]You need to define a target, username and host to be used[/]")

            if(len(host) > 2): # If the length of host variable on profile json file is greater than 2 we can assume we already have an host defined
                console.print(f"[yellow][!][/] [bright_white]Profile settings: {host}, {username}, {password}[/]", highlight=False)
                keep_data_input = Prompt.ask("[yellow][!][/] [bright_white]There is already information stored in this profile, do you want to keep it? [y/n][/]")
                keep_data_input = keep_data_input.lower()

                if(keep_data_input == 'y' or keep_data_input == 'yes'):
                    console.print("[yellow][!][/] [bright_white]Not changing current configuration[/]\n")
                    return existing_data

            target_host_input = Prompt.ask("> Type the target host (ex: 127.0.0.1)")
            username_input = Prompt.ask("> Type the username to be used (example.lab\Administrator)")
            password_input = Prompt.ask("> Type the password to be used")
            domain  = username_input.split("\\")[0]

            profile_data = {
                "host": target_host_input,
                "username": username_input,
                "password": password_input,
                "domain": domain
            }

            try:
                existing_data.update(profile_data)
                json_file.seek(0)
                json.dump(existing_data, json_file, ensure_ascii=False, indent=4)
                json_file.truncate()

                console.print("[green][+][/] [bright_white]Profile information stored successfully![/]\n")
            except Exception as error:
                console.print(f"[red][!][/] [bright_white]Error when trying to store profile information: {error}[/]")

        # return existing_data

def update_profile_settings(profile_name, data):
    ''' Upadte profile settings through JSON seek, dump and truncate '''

    settings_path = get_profile_settings_path(profile_name)
    try:
        with settings_path.open('r+') as json_file:
            json_file.seek(0)
            json.dump(data, json_file, ensure_ascii=False, indent=4)
            json_file.truncate()
        console.print("[green][+][/] [bright_white]Profile information stored successfully![/]\n")
    except Exception as error:
        console.print(f"[red][!][/] [bright_white]Error when trying to store profile information: {error}[/]")

def select_and_load_profile(inp):
    ''' Select profile based on user input '''

    profiles = list_profiles()
    if not profiles:
        return
    
    if len(inp) == 0:
        console.print("[red][!][/] [bright_white]You need to specify a profile name, use: [b]load_profile <profile_name>[/][/]")
        return True
    
    global profile_name
    profile_name = inp

    if profile_name not in [profile.name for profile in profiles]:
        console.print(f"\n[red][!][/] [bright_white]Profile [red]{profile_name}'s[/] not found, check if the name is correct[/]")
    else:
        console.print(f"\n[green][+][/] [bright_white]Profile [yellow]{profile_name}'s[/] selected successfully! [/]")
        load_profile(profile_name)

    environ["breads_profile"] = profile_name