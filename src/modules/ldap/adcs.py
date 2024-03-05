from handlers.ldap_connection import LdapHandler

from ldap3 import SUBTREE
from rich.console import Console
console = Console()

class Adcs:
    name = "adcs"
    desc = "Get 'dNSHostName' attribute value from all ADCS servers"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = f'(objectClass=pKIEnrollmentService)'
    attributes = 'dNSHostName'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options (self):
        pass

    def search_with_base(self, conn, search_base, search_filter, attributes, scope):
        return conn.search(search_base=search_base, search_filter=search_filter, search_scope=scope, attributes=attributes)

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        base = f'CN=Configuration,{base_dn}'

        results = self.search_with_base(conn, search_base=base, search_filter=self.search_filter, attributes=self.attributes, scope=SUBTREE)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            adcs_servername = res_response[0]['attributes'].get(self.attributes, '[red][!][/] No ADCS found')
            console.print("[green][+][/] Active Directory Certificate Services: ")
            console.print(adcs_servername)
        else:
            console.print("[red][!][/] No entries found in the results.")