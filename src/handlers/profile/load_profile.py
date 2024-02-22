from rich import print
from rich.prompt import Prompt
from rich.console import Console
console = Console()
from pathlib import Path
import json
import os
from uuid import uuid4

from handlers.profile.helper import BREADS_FOLDER
BREADS_FOLDER = Path(BREADS_FOLDER)

PROFILE_UUID = uuid4().hex

def list_profiles():
    ''' Lista os perfis disponíveis '''

    if not BREADS_FOLDER.exists():
        print(f"[red][!][/] .breads directory not found. Initialize one with 'create_profile' command\n")
        return []

    folders = [folder for folder in BREADS_FOLDER.iterdir() if folder.is_dir()]
    if not folders:
        print(f"[red][!][/] No profiles found in .breads directory. Create one with 'create_profile' command\n")
    else:
        for folder in folders:
            print(f"[cyan]* {folder.name}[/]")
    return folders

def get_profile_settings_path(profile_name):
    ''' Retorna o caminho do arquivo de configurações do perfil '''
    return BREADS_FOLDER / profile_name / "settings.json"

def load_profile(profile_name):
    ''' Carrega o perfil especificado '''
    settings_path = get_profile_settings_path(profile_name)

    with settings_path.open('r+') as json_file:
            existing_data = json.load(json_file)

            host     = existing_data['host']
            username = existing_data['username']
            password = existing_data['password']

            if(len(host) > 2): # If the length of host variable on profile json file is greater than 2 we can assume we already have an host defined
                console.print(f"[yellow][!][/] [bright_white]Profile settings: {host}, {username}, {password}[/]", highlight=False)
                keep_data_input = Prompt.ask("[yellow][!][/] [bright_white]There is already information stored in this profile, do you want to keep it? [y/n][/]")
                keep_data_input = keep_data_input.lower()

                if(keep_data_input == 'y' or keep_data_input == 'yes'):
                    print("[yellow][!][/] [bright_white]Not changing current configuration[/]\n")
                    pass
            else:
                target_host_input = Prompt.ask("# Type the target host (ex: 127.0.0.1)")
                username_input    = Prompt.ask("# Type the username to be used (example.lab/Administrator)")
                password_input    = Prompt.ask("# Type the password to be used")

                profile_data = {
                    "host": target_host_input,
                    "username": username_input,
                    "password": password_input
                }

                try:
                    existing_data.update(profile_data)
                    json_file.seek(0)
                    json.dump(existing_data, json_file, ensure_ascii=False, indent=4)
                    json_file.truncate()

                    print(f"[green][+][/] [bright_white]Profile information stored successfully![/]\n")
                except Exception as error:
                    print(f"[red][!][/] [bright_white]Error when trying to store profile information: {error}[/]")

        # return existing_data

def update_profile_settings(profile_name, data):
    ''' Atualiza as configurações do perfil '''

    settings_path = get_profile_settings_path(profile_name)
    try:
        with settings_path.open('r+') as json_file:
            json_file.seek(0)
            json.dump(data, json_file, ensure_ascii=False, indent=4)
            json_file.truncate()
        print(f"[green][+][/] [bright_white]Profile information stored successfully![/]\n")
    except Exception as error:
        print(f"[red][!][/] [bright_white]Error when trying to store profile information: {error}[/]")

def select_and_load_profile(inp):
    ''' Seleciona e carrega um perfil baseado na entrada do usuário '''

    profiles = list_profiles()
    if not profiles:
        return
    
    if len(inp) == 0:
        print("[red][!][/] [bright_white]You need to specify a profile name, use: [b]load_profile example[/][/]")
        
        return True
    
    global profile_name
    profile_name = inp

    if profile_name not in [profile.name for profile in profiles]:
        print(f"[red][!][/] [bright_white]Profile {profile_name}'s not found, check if the name is correct[/]")
    else:
        print(f"[green][+][/] [bright_white]Profile {profile_name}'s selected successfully! [/]")
        load_profile(profile_name)

    os.environ["breads_profile"] = profile_name