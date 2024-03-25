from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class Cpnl:
    name = "cpnl"
    desc = "Find all Users that need to change password on next login"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = "(&(objectCategory=user)(pwdLastSet=0))"
    requires_args = False
    attributes = "sAMAccountName"

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Change Password Next Login:")
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    username = entry["attributes"][self.attributes]
                    console.print(username)
        else:
            console.print("[red][!][/] No entries found in the results.")
