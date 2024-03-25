from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class PassNotReq:
    name = "password-not-required"
    desc = "List all accounts that does not need an password to authenticate"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))"
    requires_args = False
    attributes = "sAMAccountName"

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Password Not Required Accounts:")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    for _attribute, value in entry["attributes"].items():
                        console.print(f"[cyan]- [/]{value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")
