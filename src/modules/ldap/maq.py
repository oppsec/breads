from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

class Maq:
    name = "maq-account-quota"
    desc = "Get ms-DS-MachineAccountQuota value"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = '(objectClass=domainDNS)'
    requires_args = False
    attributes = 'ms-DS-MachineAccountQuota'

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2][0]
  
        if res_status:
            maq_value = res_response['attributes']['ms-DS-MachineAccountQuota']
            console.print(f" - [cyan]{self.attributes}[/]: {maq_value}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")