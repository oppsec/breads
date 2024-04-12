from ldap3 import SUBTREE
from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()


class Adcs:
    name = "adcs"
    desc = "Enumerate ADCS servers and Certificate Templates"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    search_filter = "(objectClass=pKIEnrollmentService)"
    attributes = ['*']

    def search_with_base(self, conn, search_base, search_filter, attributes, scope):
        return conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=scope,
            attributes=attributes,
        )

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        base = f"CN=Configuration,{base_dn}"

        results = self.search_with_base(
            conn,
            search_base=base,
            search_filter=self.search_filter,
            attributes=self.attributes,
            scope=SUBTREE,
        )

        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Active Directory Certificate Services (objectClass=pKIEnrollmentService):", highlight=False)

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    hostname = entry["attributes"]["dNSHostName"]
                    host_dn = entry["attributes"]["distinguishedName"]
                    host_cn = entry["attributes"]["cn"]

                    console.print(f"[cyan]-[/] Host: [cyan]{hostname}[/]\n  \_ DN: {host_dn}\n   \_ CN: {host_cn}", highlight=False)
                    try:
                        certificate_template = entry["attributes"]["certificateTemplates"]
                        if certificate_template:
                            certificates_list = []

                            for value in certificate_template:
                                certificates_list.append(value)

                            if(len(certificates_list) > 0):
                                for certificate_name in certificates_list:
                                    console.print(f"    [yellow]*[/] Certificate Template: [cyan]{certificate_name}[/]")

                    except Exception as error:
                        console.print(f"[red][!][/] Error when trying to get certificateTemplates: {error}")
                        return
                    finally:
                        console.print('\n')
        else:
            console.print("[red][!][/] No entries found in the results.")