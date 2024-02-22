from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import Connection

class Administrators:
    name = "administrators"
    desc = "Get all the accounts from domain that has administrator privilege in somewhere"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = f'(&(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))'
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
            console.print(f"[yellow][!][/] Administrator(s) usernames:", highlight=False)
            console.print("[yellow][!][/] Users listed below are not necessarily Domain Administrators, they can be Local Administrator.")
            attributes = ['sAMAccountName']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")
