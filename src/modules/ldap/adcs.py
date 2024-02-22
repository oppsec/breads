from handlers.ldap_connection import Connection

from rich.console import Console
console = Console()

class ADCS:
    name = "adcs"
    desc = "Retrieve 'dNSHostName', 'cn', 'msPKI-Enrollment-Servers  from all ADCS computers"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(objectClass=pKIEnrollmentService)'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options (self):
        pass

    def on_login(self):
        conn = Connection()
        results = conn.ldap_con(self.search_filter, conn.domain, conn.hostname, conn.username, conn.password)
  
        if results:
            console.print(f"[yellow][!][/] Querying the PKI Enrollment Servers:")
            attributes = ['dNSHostName', 'cn', 'msPKI-Enrollment-Servers']
        
            for _dn, result in results:
                for attribute_name in result:
                    for attribute in attributes:
                        if attribute_name == attribute:
                            for value in result[attribute]:
                                value = value.decode('utf-8')
                                console.print(f"[bright_white]{value}[/]")
        else:
            console.print("[red][!][/] No information found or unable to retrieve. Check your profile settings.")