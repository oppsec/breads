from pathlib import Path
import json
from rich.console import Console 
console = Console()
from ldap3 import Server, Connection, ALL, NTLM, KERBEROS, SAFE_SYNC

from handlers.profile.helper import get_current_profile, BREADS_FOLDER
BREADS_FOLDER = Path(BREADS_FOLDER)

class LdapHandler:
    def __init__(self):
        self.domain = ""
        self.password = ""
        self.username = ""
        self.hostname = ""

    def connection(self):
        if get_current_profile() == 'None':
            console.print("[red][!][/] You need to load a profile first, use 'load_profile' command")
            return None, None
        
        settings_json_file = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"

        with open(settings_json_file, 'r') as settings_file:
            data = json.load(settings_file)

            self.username = data['username']
            self.hostname = data['host']
            self.password = data['password']
            self.domain = data['domain']
        try:
            server = Server(f"ldap://{self.hostname}", use_ssl=True, get_info=ALL)
            conn = Connection(server, user=self.username, password=self.password, authentication=NTLM, client_strategy=SAFE_SYNC, auto_bind=True)
            base_dn = server.info.other['rootDomainNamingContext'][0]

            return conn, base_dn
        except Exception as error:
            console.print(f"[red][!][/] [bright_white]LDAP Error: {error}")
            return None, None
        
    def modify_entry(self, dn, mod_attrs):
        """Modifies an LDAP entry with the given attributes."""
        try:
            connect = self.connection() 
            connect.modify_s(dn, mod_attrs)
            return True
        except Exception as e:
            print(e)
            return False