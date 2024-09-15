from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

class SearchComputer:
    name = "search_computer"
    desc = "Search for all computers that have the specified word in the CN attribute"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = None
    attributes = "dNSHostName"
    requires_args = True
    min_args = 1
    usage_desc = "[yellow]Usage:[/] search_computer <word> (ex: search_computer PC)"

    def on_login(self, user_input):
        search_filter = f"(&(objectCategory=computer)(cn=*{user_input}*))"

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print(f"[green][+][/] Searching for computers with '{user_input}' in the name:")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    computer_name = entry["attributes"][self.attributes]
                    console.print(computer_name)
        else:
            console.print("[red][!][/] No entries found in the results.")