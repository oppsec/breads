from rich.console import Console
from handlers.ldap_connection import LdapHandler

import impacket
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

console = Console()


class Aces:
    name = "aces"
    desc = "Get the nTSecurityDescriptor value from all ACEs and check privileges based on current logged-on user"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = "(objectClass=*)"
    requires_args = False
    attributes = "nTSecurityDescriptor"

    # https://learn.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum
    known_aces_mask = {
        983551: "[green]FULL_CONTROL[/]",
        4: "[magenta]READ_CONTROL[/]",
        16: "[magenta]READ_PROP[/]",
        48: "[magenta]DELETE, READ_CONTROL[/]",
        8: "[magenta]WRITE_DAC[/]",
        32: "[magenta]READ_CONTROL[/]",
        131220: "[green]READ_CONTROL and more[/]",
        983485: "[green]DELETE, READ_CONTROL and more[/]",
        256: "[magenta]CONTROL_ACCESS[/]",
        3: "[magenta]WRITE_DAC and WRITE_OWNER[/]",
        65536: "[red]DELETE_CHILD[/]",
        4294967295: "[green]FULL_CONTROL[/]",
        524288: "[magenta]SELF[/]",
        131072: "[magenta]CONTROL[/]",
        524288: "[magenta]WRITE_OWNER[/]",
        1048576: "[magenta]SYNCHRONIZE[/]",
        16777216: "[magenta]ACCESS_SYSTEM_SECURITY[/]",
        536870912: "[magenta]GENERIC_EXECUTE[/]",
        268435456: "[green]GENERIC_ALL[/]",
        32: "[magenta]WRITE_PROP[/]",
        64: "[magenta]DELETE_TREE[/]",
        128: "[magenta]LIST_OBJECT[/]",
        1: "[magenta]READ[/]"
    }

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)

        console.print("[yellow][!][/] Enumerating all ACEs and checking permissions, this may take a long time...")

        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        impacket.ldap.ldaptypes.RECALC_ACE_SIZE = False
        processed_aces = set()

        if res_status:
            for attribute in res_response:
                if attribute["type"] == "searchResEntry":
                    object_dn = attribute["dn"]
                    object_ntsd = attribute["attributes"]["nTSecurityDescriptor"]

                    if len(object_ntsd) == 0:
                        console.print("[red][!][/] No interesting or privilege above ACEs found :(")
                        return

                    sd = SR_SECURITY_DESCRIPTOR(data=object_ntsd)

                    # owner_sid = (
                    #     sd["OwnerSid"].formatCanonical() if sd["OwnerSid"] else "None"
                    # )
                    # group_sid = (
                    #     sd["GroupSid"].formatCanonical() if sd["GroupSid"] else "None"
                    # )

                    if sd["Dacl"]:
                        for ace in sd["Dacl"].aces:
                            ace_typename = ace["TypeName"]
                            ace_object = ace["Ace"]  # Ace_Object Vars: Mask, Sid
                            ace_mask = ace_object["Mask"]["Mask"]
                            ace_sid = ace_object["Sid"].formatCanonical()

                            ace_key = f"{object_dn}-{ace_typename}-{ace_sid}-{ace_mask}"
                            if ace_key in processed_aces:
                                continue
                            processed_aces.add(ace_key)

                            if (ace_typename == "ACCESS_ALLOWED_OBJECT_ACE" or ace_typename == "ACCESS_ALLOWED_ACE"):
                                if ace_mask in self.known_aces_mask:
                                    permission = self.known_aces_mask[ace_mask]
                                    console.print(f"[cyan]-[/] DN: {object_dn}\n[cyan]*[/] SID: [yellow]{ace_sid}[/]\n[cyan]*[/] Privileges: {permission} ({ace_mask})\n", highlight=False)
                                else:
                                    console.print(f"[cyan]-[/] DN: {object_dn}\n[cyan]*[/] SID: [yellow]{ace_sid}[/]\n[cyan]*[/] Unknown privileges: {ace_mask}\n", highlight=False)
                    else:
                        console.print("[red]DACL is None[/]")
        else:
            console.print("[red][!][/] No entries found in the results.")
