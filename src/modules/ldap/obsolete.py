from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import Connection

class Obsolete:
    name = "obsolete"
    desc = "Search for obsolete operating systems installed on computers and get 'dNSHostName', 'operatingSystem' from target"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = ("(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
                         "(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)"
                         "(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)"
                         "(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)"
                         "(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)"
                         "(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2000*)))")
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
            attributes = ['dNSHostName', 'operatingSystem']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")
