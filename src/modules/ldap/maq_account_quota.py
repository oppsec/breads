from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import Connection

class MaqAccountQuota:
    name = "maq_account_quota"
    desc = "Get the Macchine Account Quota value domain-level attribute"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = '(objectClass=*)'
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
            console.print(f"[yellow][!][/] Querying Machine Account Quota value:")
            attributes = ['ms-DS-MachineAccountQuota']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")
