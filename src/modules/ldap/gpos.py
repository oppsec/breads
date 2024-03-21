from handlers.ldap_connection import LdapHandler

from rich.console import Console
console = Console()

class Gpos:
    name = "Gpos"
    desc = "List the GPOs registed in the domain"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(objectClass=groupPolicyContainer)'
    requires_args = False
    attributes = ['displayName', 'gPCFileSysPath']

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        gpo_info = {}
        gpo_infos = []

        if res_status:
            console.print("[green][+][/] GPOs:")

            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    gpo_info = {}
                    for attribute, value in entry['attributes'].items():
                        gpo_info[attribute] = value
                    gpo_infos.append(gpo_info)

            for gpo_info in gpo_infos:
                gpo_name = gpo_info.get('displayName', [])       
                gpo_path = gpo_info.get('gPCFileSysPath', [])
                console.print(f'[cyan]- {gpo_name}[/]: {gpo_path}', highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")