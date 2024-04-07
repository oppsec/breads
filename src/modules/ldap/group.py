from rich.console import Console
from re import search

from handlers.ldap_connection import LdapHandler
from helpers.manager import list_attribute_handler

console = Console()


class Group:
    name = "group"
    desc = "Get information from the group name specified"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    requires_args = True
    attributes = [
        "objectClass",
        "cn",
        "member",
        "distinguishedName",
        "memberOf",
        "objectSid",
        "sAMAccountName",
        "description"
    ]
    min_args = 1

    def on_login(self, *args) -> None:
        console.print("[yellow]WARNING:[/] You can use % or ' to specify the space between the group name. [yellow]Domain%Admins[/] or [yellow]'Domain Admins'[/]\n", highlight=False)

        group_name = args[0]
        group = group_name.replace("%", " ")

        if not group_name or len(group_name) < 1:
            console.print("[red]Usage:[/] group <group_name>")
            return

        search_filter = f"(&(objectClass=group)(cn={group}))"

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        group_info = {}
        seen_attributes = set()

        if res_status:
            console.print(f"[green][+][/] {group_name}'s group information:")

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    for attribute, value in entry["attributes"].items():
                        if attribute not in seen_attributes:
                            group_info[attribute] = value
                            seen_attributes.add(attribute)

            for desc in group_info.get("description", []):
                group_info["description"] = desc
                            
            for attribute, value in group_info.items():
                list_attribute_handler(attribute, value)
        else:
            console.print("[red][!][/] No entries found in the results.")
