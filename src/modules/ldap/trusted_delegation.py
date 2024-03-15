from handlers.ldap_connection import LdapHandler

from rich.console import Console
console = Console()

class TrustedDelegation:
    name = "trusted-delegation"
    desc = "Get 'sAMAccountName' from accounts that has 'msds-allowedtodelegateto' enabled"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
    requires_args = False
    attributes='sAMAccountName'

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Trusted Delegation Users/Computers:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    hostname = entry['attributes'][self.attributes]
                    console.print(hostname)
        else:
            console.print("[red][!][/] No entries found in the results.")