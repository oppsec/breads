from handlers.ldap_connection import LdapHandler

from rich.console import Console
from ldap3 import SUBTREE

console = Console()


class DomainSid:
    name = "DomainSID"
    desc = "Get SID from Domain Controllers"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
    attributes = ["cn", "objectSid", "dNSHostName"]

    def search_with_base(self, conn, search_base, search_filter, attributes, scope):
        return conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
        )

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = self.search_with_base(
            conn,
            search_base=base_dn,
            search_filter=self.search_filter,
            attributes=self.attributes,
            scope=SUBTREE,
        )
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Domain SID:")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    
                    domain_cn = entry["attributes"]["cn"]
                    domain_objectSid = entry["attributes"]["objectSid"]
                    domain_dNSHostName = entry["attributes"]["dNSHostName"]

                    console.print(f"[cyan]-[/] [yellow]{domain_objectSid}[/] - {domain_dNSHostName} - {domain_cn}\n", highlight=False)   
        else:
            console.print("[red][!][/] No entries found in the results.")
