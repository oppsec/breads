from ldap3 import Server, Connection, ALL, NTLM, SAFE_SYNC
from ldap3.core.exceptions import LDAPSocketOpenError, LDAPBindError
from pathlib import Path
from json import load
from rich.console import Console
from sys import exit

from handlers.profile.helper import get_current_profile, BREADS_FOLDER

BREADS_FOLDER = Path(BREADS_FOLDER)

console = Console()


class LdapHandler:
    """BREAD's default LDAP handler class"""

    def __init__(self):
        self.domain = ""
        self.password = ""
        self.username = ""
        self.hostname = ""

    def connection(self) -> None:
        """Default LDAP connection handler"""

        if get_current_profile() == "None":
            console.print("[red][!][/] You need to load a profile first, use 'load_profile' command")
            return None, None

        prifle_json = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"
        with open(prifle_json, "r") as settings_file:
            data = load(settings_file)

            self.username = data["username"]
            self.hostname = data["host"]
            self.password = data["password"]
            self.domain = data["domain"]

            if len(self.password) == 32 and all(c in "0123456789abcdefABCDEF" for c in self.password):
                self.password = f'aad3b435b51404eeaad3b435b51404ee:{self.password}'

        try:
            server = Server(f"ldaps://{self.hostname}", use_ssl=True, get_info=ALL)
            conn = Connection(server, user=self.username, password=self.password,
                              authentication=NTLM, client_strategy=SAFE_SYNC,
                              auto_bind=True)
            
            base_dn = server.info.other["defaultNamingContext"][0]
            return conn, base_dn
            
        except LDAPSocketOpenError:
            try:
                server = Server(f"ldap://{self.hostname}", use_ssl=False, get_info=ALL)
                conn = Connection(server, user=self.username, password=self.password,
                                  authentication=NTLM, client_strategy=SAFE_SYNC,
                                  auto_bind=True)
                
                base_dn = server.info.other["defaultNamingContext"][0]
                return conn, base_dn

            except Exception as error:
                console.print(f"[red][!][/] Failed to authenticate to {self.domain} Active Directory (NO SSL): {error}")
                exit(0)

        except LDAPBindError as error:
            console.print(f"[red][!][/] Failed to authenticate to {self.domain} Active Directory (NO SSL): {error}")
            exit(0)

        except Exception as error:
            console.print(f"[red][!][/] Failed to authenticate to {self.domain} Active Directory (SSL): {error}")
            exit(0)

    def modify_entry(self, dn, mod_attrs) -> None:
        """Modifies an LDAP entry with the given attributes"""

        try:
            connect = self.connection()
            connect.modify_s(dn, mod_attrs)
            return True
        except Exception as e:
            console.print(f"[red][!][/] Error: {e}")
            return False
