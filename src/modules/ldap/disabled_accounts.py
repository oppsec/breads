from handlers.ldap_connection import LdapHandler

from rich.console import Console
console = Console()

class DisabledAccounts:
    name = "disabled-accounts"
    desc = "Get 'sAMAccountName' attribute value from Disabled Accounts"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))'
    attributes = 'sAMAccountName'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options (self):
        pass

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Disabled Accounts:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    username = entry['attributes'][self.attributes]
                    console.print(username)
        else:
            console.print("[red][!][/] No entries found in the results.")