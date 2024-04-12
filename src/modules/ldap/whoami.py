from rich.console import Console
from re import search

from handlers.ldap_connection import LdapHandler
from helpers.manager import list_attribute_handler

console = Console()


class Whoami:
    name = "whoami"
    desc = "Extract information from a desired account through user input"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = None
    requires_args = True
    min_args = 1
    attributes = [
        "description",
        "memberOf",
        "userAccountControl",
        "badPwdCount",
        "lastLogoff",
        "lastLogon",
        "objectSid",
        "adminCount",
        "accountExpires",
        "sAMAccountName",
        "servicePrincipalName"
    ]
    usage_desc = "[yellow]Usage:[/] whoami <username> (ex: whoami Administrator)"

    uac_values = {
        "512": "[bold green]User is Enabled[/] - Password Expires",
        "514": "[bold red]User is Disabled[/] - Password Expires",
        "66048": "[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/]",
        "66050": "[bold red]User is Disabled[/] - [bold yellow]Password Never Expires[/]",
        "1114624": "[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/] - User Not Delegated",
        "1049088": "[bold green]User is Enabled[/] - Password Expires - User Not Delegated",
        "17891840": "[bold green]User is Enabled[/] - [bold yellow]Password Never Expires[/] - [bold yellow]User Trusted to Delegate[/]",
        "66176": "[bold yellow]Password Never Expires[/] - [bold yellow]ms-DS-User-Encrypted-Text-Password-Allowed is true[/]",
        "4096": "[yellow]WORKSTATION_TRUST_ACCOUNT[/]",
    }

    def on_login(self, target: str):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(
            base_dn,
            f"(&(objectClass=user)(sAMAccountName={target}))",
            attributes=self.attributes,
        )
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print(f"[green][+][/] Whoami [yellow]{target}[/]:", highlight=False)
            user_info = {}
            seen_attributes = set()
            uac_printed = False

            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    for attribute, value in entry["attributes"].items():
                        if attribute not in seen_attributes:
                            user_info[attribute] = value
                            seen_attributes.add(attribute)

            # Translate userAccountControl value
            uac_value = user_info.get("userAccountControl")
            for value, description in self.uac_values.items():
                if str(uac_value) == str(value) and not uac_printed:
                    user_info["userAccountControl"] = description
                    uac_printed = True

            # Avoid KeyError on 'description' attribute
            for desc in user_info.get("description", []):
                user_info["description"] = desc

            # Process memberOf attribute
            for attribute, value in user_info.items():
                list_attribute_handler(attribute, value)
        else:
            console.print("[red][!][/] No entries found in the results.")
