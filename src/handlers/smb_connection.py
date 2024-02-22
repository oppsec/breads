from impacket.smbconnection import SMBConnection
from rich.console import Console
from pathlib import Path
import json

from handlers.profile.helper import get_current_profile, BREADS_FOLDER

console = Console()
BREADS_FOLDER = Path(BREADS_FOLDER)

class SMBConnectionManager:
    def __init__(self):
        self.username = ""
        self.password = ""
        self.domain = ""

    def load_profile_settings(self):
        if get_current_profile() == 'None':
            console.print("[red][!][/] You need to load a profile first, use 'load_profile' command")
            return False
        
        settings_json_file = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"

        try:
            with open(settings_json_file, 'r') as settings_file:
                data = json.load(settings_file)

                self.username = data.get('username')
                self.password = data.get('password')

                return True
        except FileNotFoundError:
            console.print("[red][!][/] Could not find the settings file.")
            return False
        except json.JSONDecodeError:
            console.print("[red][!][/] Invalid JSON format in settings file.")
            return False

    def get_smb_connection(self, target):
        if not self.load_profile_settings():
            return None
        
        try:
            smb_connection = SMBConnection(target, target)
            
            if '/' in self.username:
                domain, username = self.username.split('/', 1)
            else:
                domain = '' 
                username = self.username

            smb_connection.login(username, self.password, domain=domain)
            return smb_connection
        except Exception as e:
            console.print(f"[red][!][/] Error establishing SMB connection: {e}")
            return None

