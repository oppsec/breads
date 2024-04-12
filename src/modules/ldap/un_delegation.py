from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class UnDelegation:
    name = "unconstrained-delegation"
    desc = "List accounts and computers vulnerable to Unconstrained Delegation"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
    requires_args = False
    attributes = "sAMAccountName"

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Unconstrained Delegation Users/Computers (will include DCs):")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    samAccountName = entry["attributes"][self.attributes]
                    console.print(samAccountName)
        else:
            console.print("[red][!][/] No entries found in the results.")
