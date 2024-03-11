from handlers.ldap_connection import LdapHandler    

from rich.console import Console
console = Console()

from re import search 

class Computer:
    name = "Computer"
    desc = "Get specific computer information"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = None
    attributes = ['cn', 'whenCreated', 'objectSid', 'operatingSystem', 'sAMAccountName', 'dNSHostName']
    min_args = 1
    require_args = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options    

    def options (self):
        pass

    def on_login(self, target: str):

        conn, base_dn = LdapHandler.connection(self)
        search_filter = f"(&(objectClass=computer)(sAMAccountName={target}))"
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if not target or len(target) < 1:
            console.print("[red]Usage:[/] computer <target>")
            return

        if res_status:
            console.print(f"[green][+][/] Computer [yellow]{target}[/]")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    for key, value in entry['attributes'].items():
                            
                            if key == 'objectSid':
                                match = search(r"\d{4}$", value)
                                if match:
                                    console.print(f"[green][+][/] RID: {match.group()}", highlight=False)

                            console.print(f"[green][+][/] {key}: {value}", highlight=False)

        else:
            console.print("[red][!][/] No entries found in the results.")