from ldap3 import SUBTREE
from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

class Adcs:
    name = "adcs"
    desc = "Get 'dNSHostName' attribute value from all ADCS servers"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(objectClass=pKIEnrollmentService)'
    attributes = ['cn', 'dNSHostName', 'distinguishedName']

    def search_with_base(self, conn, search_base, search_filter, attributes, scope):
        return conn.search(search_base=search_base, search_filter=search_filter, search_scope=scope, attributes=attributes)

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        base = f'CN=Configuration,{base_dn}'

        results = self.search_with_base(conn, search_base=base, search_filter=self.search_filter, attributes=self.attributes, scope=SUBTREE)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Active Directory Certificate Services:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    for attribute, value in entry['attributes'].items():
                            console.print(f" - [cyan]{attribute}[/]: {value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")