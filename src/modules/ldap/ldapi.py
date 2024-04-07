from rich.console import Console
from handlers.ldap_connection import LdapHandler
from helpers.manager import list_attribute_handler

console = Console()


class Ldapi:
    name = "ldapi"
    desc = "Execute custom LDAP queries"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = None
    requires_args = True
    min_args = 2
    attributes = None

    def on_login(self, ldap_query, query_attributes):
        conn, base_dn = LdapHandler.connection(self)

        if(len(ldap_query) <= 0):
            console.print("[yellow][!][/] You need to specify a LDAP query")
            return
        
        attribute_list = [attr.strip() for attr in query_attributes.split(',')]
        results = conn.search(base_dn,ldap_query, attributes=attribute_list)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] LDAP query:")
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    attributes = entry["attributes"]
                    for attribute, value in attributes.items():
                        list_attribute_handler(attribute, value)
        else:
            console.print("[red][!][/] No entries found in the results.")
