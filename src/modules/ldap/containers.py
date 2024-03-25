from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

class Containers:
    name = "containers"
    desc = "Get 'name' and 'distinguishedName' from all Containers"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = '(objectCategory=container)'
    requires_args = False
    attributes = ['name', 'distinguishedName']
    
    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Containers:")

            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    name = entry['attributes']['name']
                    dn = entry['attributes']['distinguishedName']
                    console.print(f"[cyan]- [/]{name} - [yellow]{dn}[/]", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")