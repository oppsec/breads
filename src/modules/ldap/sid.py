from typing import Optional, Dict
from rich.console import Console
console = Console()
from ldap3.protocol.formatters.formatters import format_sid

from handlers.ldap_connection import LdapHandler

class Sid:
    name = "sid"
    desc = "Get object information from specified SID"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    requires_args = True
    attributes = ['*']
    min_args = 1

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options: Optional[Dict] = module_options

    def options (self):
        pass

    def on_login(self, sid: str) -> None:

        if not sid or len(sid) < 1:
            console.print("[red]Usage:[/] sid <SID>")
            return
        
        sid_bytes = format_sid(sid)
        search_filter = f'(objectSid={sid_bytes})'

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] SID Information:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    for key, value in entry['attributes'].items():
                        console.print(f"[green][+][/] {key}: {value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")