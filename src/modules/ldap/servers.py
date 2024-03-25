from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class Servers:
    name = "servers"
    desc = "Get 'sAMAccountName', 'operatingSystem' and 'dnsHostName' from all Servers"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = "(&(objectCategory=computer)(operatingSystem=*server*))"
    requires_args = False
    attributes = ["sAMAccountName", "operatingSystem", "dNSHostName"]

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Servers:")
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    hostname = entry["attributes"]["sAMAccountName"]
                    version = entry["attributes"]["operatingSystem"]
                    dnshostname = entry["attributes"]["dNSHostName"]
                    console.print(
                        f"[cyan]- [/]{hostname} - {version} - {dnshostname}",
                        highlight=False,
                    )
        else:
            console.print("[red][!][/] No entries found in the results.")
