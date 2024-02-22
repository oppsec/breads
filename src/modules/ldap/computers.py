from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import Connection

class Computers:
    name = "computers"
    desc = "Return all the computers that can be located"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    requires_args = False

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options: Optional[Dict] = module_options

    def options (self):
        pass

    def on_login(self):
        conn = Connection()
        results = conn.ldap_con(self.search_filter, conn.domain, conn.hostname, conn.username, conn.password)
  
        if results:
            console.print(f"[yellow][!][/] Computers found:", highlight=False)
            attributes = ['sAMAccountName', 'name', 'operatingSystem', 'dNSHostName']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")
