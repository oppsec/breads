from rich.console import Console
from ldap3.protocol.formatters.formatters import format_sid

from handlers.ldap_connection import LdapHandler
from helpers.manager import list_attribute_handler

console = Console()


class Sid:
    name = "sid"
    desc = "Get object information from specified SID"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    requires_args = True
    attributes = ["objectClass"]
    min_args = 1
    usage_desc = "[yellow]Usage:[/] sid <SID> (ex: sid S-1-5-21-38104105-1020608657-3706787590-1001)"

    def process_info(self, conn, base_dn, search_filter, attribute_list):
        search = conn.search(base_dn, search_filter, attributes=attribute_list)
        search_response = search[2]

        for entry in search_response:
            if entry["type"] == "searchResEntry":
                attributes = entry["attributes"]
                for attribute, value in attributes.items():
                    list_attribute_handler(attribute, value)
                    #console.print(f" - [cyan]{attribute}[/]: {value}", highlight=False)

    def on_login(self, sid: str) -> None:

        sid_bytes = format_sid(sid)
        search_filter = f"(objectSid={sid_bytes})"

        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        sid_info = {}
        seen_attributes = set()

        if res_status:
            console.print("[green][+][/] SID Information:")
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    for attribute, value in entry["attributes"].items():
                        if attribute not in seen_attributes:
                            sid_info[attribute] = value
                            seen_attributes.add(attribute)

            objectClass_value = sid_info.get("objectClass", [])
            console.print(f"[yellow italic] \_ objectClass: {objectClass_value}[/]")

            if "computer" in objectClass_value:
                computer_attrs = [
                    "cn",
                    "distinguishedName",
                    "memberOf",
                    "objectSid",
                    "operatingSystem",
                    "dNSHostName",
                ]
                self.process_info(conn, base_dn, search_filter, computer_attrs)

            elif "user" in objectClass_value:
                user_attrs = [
                    "cn",
                    "description",
                    "distinguishedName",
                    "memberOf",
                    "whenCreated",
                    "name",
                    "userAccountControl",
                    "badPwdCount",
                    "lastLogon",
                    "objectSid",
                    "sAMAccountName",
                ]
                self.process_info(conn, base_dn, search_filter, user_attrs)

            elif "group" in objectClass_value:
                group_attrs = [
                    "cn",
                    "member",
                    "distinguishedName",
                    "whenCreated",
                    "memberOf",
                    "objectGUID",
                    "objectSid",
                ]
                self.process_info(conn, base_dn, search_filter, group_attrs)
            else:
                console.print("[yellow] objectClass type not identified, returning all attributes.[/]")
                self.process_info(conn, base_dn, search_filter, ["*"])
        else:
            console.print("[red][!][/] No entries found in the results.")
