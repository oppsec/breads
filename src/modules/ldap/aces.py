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
        65536: "The right to delete the object.",
        131072: "The right to read data from the security descriptor of the object, not including the data in the SACL.",
        262144: "The right to modify the discretionary access-control list (DACL) in the object security descriptor.",
        524288: "The right to assume ownership of the object. The user must be an object trustee. The user cannot transfer the ownership to other users.",
        1048576: "The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.",
        16777216: "The right to get or set the SACL in the object security descriptor.",
        2147483648: "The right to read permissions on this object, read all the properties on this object, list this object name when the parent container is listed, and list the contents of this object if it is a container.",
        1073741824: "The right to read permissions on this object, write all the properties on this object, and perform all validated writes to this object.",
        536870912: "The right to read permissions on, and list the contents of, a container object.",
        268435456:"The right to create or delete child objects, delete a subtree, read and write properties, examine child objects and the object itself, add and remove the object from the directory, and read or write with an extended right.",
        1: "The right to create child objects of the object. The ObjectType member of an ACE can contain a GUID that identifies the type of child object whose creation is controlled. If ObjectType does not contain a GUID, the ACE controls the creation of all child object types.",
        2: "The right to delete child objects of the object. The ObjectType member of an ACE can contain a GUID that identifies a type of child object whose deletion is controlled. If ObjectType does not contain a GUID, the ACE controls the deletion of all child object types.",
        4: "The right to list child objects of this object. (AD - Controlling Object Visibility)",
        8: "The right to perform an operation controlled by a validated write access right. The ObjectType member of an ACE can contain a GUID that identifies the validated write. If ObjectType does not contain a GUID, the ACE controls the rights to perform all valid write operations associated with the object.",
        16: "The right to read properties of the object. The ObjectType member of an ACE can contain a GUID that identifies a property set or property. If ObjectType does not contain a GUID, the ACE controls the right to read all of the object properties.",
        32: "The right to write properties of the object. The ObjectType member of an ACE can contain a GUID that identifies a property set or property. If ObjectType does not contain a GUID, the ACE controls the right to write all of the object properties.",
        64: "The right to delete all child objects of this object, regardless of the permissions of the child objects.",
        128: "The right to list a particular object. If the user is not granted such a right, and the user does not have ADS_RIGHT_ACTRL_DS_LIST set on the object parent, the object is hidden from the user. This right is ignored if the third character of the dSHeuristics property is '0' or not set.",
        256: "The right to perform an operation controlled by an extended access right. The ObjectType member of an ACE can contain a GUID that identifies the extended right. If ObjectType does not contain a GUID, the ACE controls the right to perform all extended right operations associated with the object.",
        983551: "FULL_CONTROL (Not confirmed)",
        131220: "READ_CONTROL and more (Not confirmed)",
        983485: "DELETE, READ_CONTROL and more (Not confirmed)",
        3: "WRITE_DAC and WRITE_OWNER (Not confirmed)",
        4294967295: "FULL_CONTROL (Not confirmed)"
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
                                    console.print(f"[cyan]-[/] DN: {object_dn}\n[cyan]*[/] SID: [yellow]{ace_sid}[/]\n[cyan]*[/] Privileges: {permission} [yellow]({ace_mask})[/]\n", highlight=False)
                                else:
                                    console.print(f"[cyan]-[/] DN: {object_dn}\n[cyan]*[/] SID: [yellow]{ace_sid}[/]\n[cyan]*[/] Unknown privileges: {ace_mask}\n", highlight=False)
                    else:
                        console.print("[red]DACL is None[/]")
        else:
            console.print("[red][!][/] No entries found in the results.")
