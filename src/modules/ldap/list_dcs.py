from handlers.ldap_connection import Connection

from rich.console import Console
console = Console()

class ListDcs:
    name = "list-dcs"
    desc = "Retrieve 'dNSHostName' from all Domain Controllers that can be found on Active Directory"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options (self):
        pass

    def on_login(self):
        conn = Connection()
        results = conn.ldap_con(self.search_filter, conn.domain, conn.hostname, conn.username, conn.password)
  
        if results:
            console.print(f"[yellow][!][/] Domain Controllers:")
            attributes = ['dNSHostName']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")