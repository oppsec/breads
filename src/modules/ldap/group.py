from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

class Group:
    name = "group"
    desc = "Get information from the group name specified"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    requires_args = True
    attributes = ['objectClass', 'cn', 'member', 'distinguishedName', 'memberOf', 'objectSid', 'sAMAccountName']
    min_args = 1

    def on_login(self, *args) -> None:
        console.print("[yellow]WARNING:[/] The space between the group name need to be replaced with '%'. Example: [green]Domain%Admins[/]. Or you can use 'Domain Admins'\n")

        group_name = args[0]
        group = group_name.replace("%", " ")

        if not group_name or len(group_name) < 1:
            console.print("[red]Usage:[/] group <group_name>")
            return
        
        search_filter = f'(&(objectClass=group)(cn={group}))'

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print(f"[green][+][/] {group_name}'s information:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    for attribute, value in entry['attributes'].items():
                        console.print(f" - [cyan]{attribute}[/]: {value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")