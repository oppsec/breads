from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import LdapHandler

class Computers:
    name = "computers"
    desc = "Return all the computers that can be located"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = '(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    requires_args = False
    attributes='dNSHostName'
    
    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Computers:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    hostname = entry['attributes'][self.attributes]
                    console.print(hostname)
        else:
            console.print("[red][!][/] No entries found in the results.")