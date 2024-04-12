from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class Obsolete:
    name = "obsolete"
    desc = "Search for computers with obsolete operating systems"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = (
        "(&(objectclass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(|(operatingSystem=*Windows 6*)(operatingSystem=*Windows 2000*)"
        "(operatingSystem=*Windows XP*)(operatingSystem=*Windows Vista*)"
        "(operatingSystem=*Windows 7*)(operatingSystem=*Windows 8*)"
        "(operatingSystem=*Windows 8.1*)(operatingSystem=*Windows Server 2003*)"
        "(operatingSystem=*Windows Server 2008*)(operatingSystem=*Windows Server 2000*)))"
    )
    requires_args = False
    attributes = ["dNSHostName", "operatingSystem"]

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Obsolete Computers:")
            
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    hostname = entry["attributes"]["dnsHostName"]
                    version = entry["attributes"]["operatingSystem"]
                    console.print(f"[cyan]- [/]{hostname} - {version}", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")
