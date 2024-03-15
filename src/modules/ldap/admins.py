from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import LdapHandler

class Admins:
    name = "admins"
    desc = "Get all the accounts from domain that has administrator privilege in somewhere"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = f'(&(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))(adminCount=1))'
    requires_args = False
    attributes = 'sAMAccountName'

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Domain Administrators and Local Administrators:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    username = entry['attributes'][self.attributes]
                    console.print(username)
        else:
            console.print("[red][!][/] No entries found in the results.")