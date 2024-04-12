from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class SearchGroup:
    name = "search_group"
    desc = "Search for all groups that has specify word on CN attribute"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = None
    attributes = "sAMAccountName"
    requires_args = True
    min_args = 1
    usage_desc = "[yellow]Usage:[/] search_group <word> (ex: search_group Admin)"

    def on_login(self, user_input):
        search_filter = f"(&(objectCategory=group)(cn=*{user_input}*))"

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print(f"[green][+][/] Searching for groups with '{user_input}' on the name:")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    group_name = entry["attributes"][self.attributes]
                    console.print(group_name)
        else:
            console.print("[red][!][/] No entries found in the results.")
