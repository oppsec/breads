from rich.console import Console
from re import search
from handlers.ldap_connection import LdapHandler

console = Console()


class Computer:
    name = "Computer"
    desc = "Get specific computer information"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = None
    attributes = [
        "cn",
        "whenCreated",
        "objectSid",
        "operatingSystem",
        "sAMAccountName",
        "dNSHostName",
    ]
    min_args = 1
    require_args = True
    usage_desc = "[yellow]Usage:[/] computer <computer_name> (ex: computer TEST$)"

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
                if entry["type"] == "searchResEntry":
                    for attribute, value in entry["attributes"].items():

                        if attribute == "objectSid":
                            match = search(r"\d{4}$", value)
                            if match:
                                console.print(f" - [cyan]RID[/]: {match.group()}", highlight=False)

                        console.print(f" - [cyan]{attribute}[/]: {value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")
