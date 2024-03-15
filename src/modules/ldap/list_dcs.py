from handlers.ldap_connection import LdapHandler

from rich.console import Console
console = Console()

class ListDcs:
    name = "list-dcs"
    desc = "Get 'dNSHostName' attribute value from all Domain Controllers"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
    attributes = 'dnsHostname'

    def get_dc_name(self):
        conn, base_dn = LdapHandler.connection(self)

        if conn is None:
            console.print("[red][!][/] Failed to establish LDAP connection.")
            return []
        
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_response = results[2]
        dcs_list = []

        for entry in res_response:
            if entry['type'] == 'searchResEntry':
                hostname = entry['attributes'][self.attributes]
                dcs_list.append(hostname)
        return dcs_list
                

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        dcs_list = []

        if res_status:
            console.print("[green][+][/] Domain Controllers:")
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    hostname = entry['attributes'][self.attributes]
                    dcs_list.append(hostname)

                    for dc in dcs_list:
                        console.print(dc)
        else:
            console.print("[red][!][/] No entries found in the results.")