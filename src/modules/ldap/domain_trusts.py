from rich.console import Console
from handlers.ldap_connection import LdapHandler
from handlers.sid_translate import binary_sid_to_string

console = Console()


class DomainTrusts:
    name = "domain-trusts"
    desc = "Get Domain Trusts"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = "(objectClass=trustedDomain)"
    attributes = [
        "cn",
        "distinguishedName",
        "objectGUID",
        "securityIdentifier",
        "trustDirection",
    ]

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        # Resource: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
        trust_direction_map = {
            0: "[red]TRUST_DIRECTION_DISABLED [0] (-)[/]",
            1: "[yellow]TRUST_DIRECTION_INBOUND [1] (->)[/]",
            2: "[yellow]TRUST_DIRECTION_OUTBOUND [2] (<-)[/]",
            3: "[green]TRUST_DIRECTION_BIDIRECTIONAL [3] (<->)[/]",
        }

        if res_status:
            console.print("[green][+][/] Domain Trusts:")

            for entry in res_response:
                for key, value in entry.items():
                    if key == "attributes":
                        for attr, desc in value.items():
                            if attr == "trustDirection":
                                desc = trust_direction_map.get(desc, desc)

                            if attr == "securityIdentifier":
                                desc = binary_sid_to_string(desc)

                            if attr == "cn":
                                desc = f"[yellow]{desc}[/]"

                            console.print(
                                f"[cyan] - [/] {attr}: {desc}", highlight=False
                            )
        else:
            console.print("[red][!][/] No entries found in the results.")
