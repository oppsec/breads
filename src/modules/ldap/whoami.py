from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import Connection
from handlers.ft_to_dt import filetime_to_dt

class Whoami:
    name = "whoami"
    desc = "Extract information from a desired account through user input"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = None
    requires_args = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options: Optional[Dict] = module_options

    def options (self):
        pass

    def print_user_info(self, results):
        attributes = ['sAMAccountName', 'distinguishedName', 'memberOf', 'lastLogon', 'lastLogoff', 'userAccountControl']
        uac_values = {
            '512': '[bold green]User is Enabled[/] - Password Expires',
            '514': '[bold red]User is Disabled[/] - Password Expires',
            '66048': "[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/]",
            '66050': "[bold red]User is Disabled[/] - [bold yellow]Password Never Expires[/]",
            '1114624': '[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/] - [bold yellow]User Not Delegated[/]',
            '1049088': "[bold green]User is Enabled[/] - Password Expires - [bold yellow]User Not Delegated[/]",
            '17891840': '[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/] - [bold yellow]User Trusted to Delegate[/]'
        }

        for _dn, result in results:
            for attribute_name in result:
                if attribute_name in attributes:
                    for value in result[attribute_name]:
                        value = value.decode('utf-8')
                        self.process_attribute(attribute_name, value, uac_values)

    def process_attribute(self, attribute_name, value, uac_values):
        if attribute_name == "userAccountControl":
            console.print(f"[green][+][/] UAC Status: [bright_white]{uac_values.get(value, 'Unknown')}[/]", highlight=False)
        elif attribute_name in ["lastLogon", "lastLogoff"] and value != "0":
            dt = filetime_to_dt(int(value))
            console.print(f"[green][+][/] {attribute_name} (DT): [bright_white]{dt}[/]", highlight=False)
        else:
            console.print(f"[green][+][/] [bright_white]{attribute_name}: {value}[/]", highlight=False)

    def on_login(self, target: str):
        if not target or len(target.split()) < 1:
            console.print("[red]Usage:[/] whoami <username>")
            return

        user_target = target.split()[0]
        conn = Connection()
        results = conn.ldap_con(f'(&(objectClass=user)(sAMAccountName={user_target}))', conn.domain, conn.hostname, conn.username, conn.password)

        if results:
            console.print(f"[yellow][!][/] Whoami {user_target}:")
            self.print_user_info(results)
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")