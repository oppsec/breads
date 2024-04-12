from rich.console import Console
from handlers.ldap_connection import LdapHandler

console = Console()

# *******************************
# * WORKFLOW
# * 1. Capture username and group desired based on user input
# * 2. Check if specified user exists on the Active Directory
# * 3. Try changing user password
# *******************************


class ChangePassword:
    name = "change-password"
    desc = "Change desired user password"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = None
    requires_args = True
    min_args = 2
    attributes = "sAMAccountName"
    usage_desc = "[yellow]Usage:[/] change_password <username> <new_password>"

    def get_user_dn(self, conn, base_dn, target):
        dn_query = conn.search(base_dn, f"(&(objectClass=user)(sAMAccountName={target}))", attributes=["*"])
        dn_response = dn_query[2]
        return dn_response

    def on_login(self, *args):

        target = args[0]
        new_pass = args[1]

        try:
            conn, base_dn = LdapHandler.connection(self)
            console.print(f"[green][+][/] Changing user [yellow]{target}[/] password to [yellow]{new_pass}[/]")

            user_dn = self.get_user_dn(conn, base_dn, target)

            if not user_dn[0]["type"] == "searchResEntry":
                console.print("[red][!][/] User not found or LDAP search failed.")
                return

            user_dn = user_dn[0]["raw_dn"].decode("utf-8")
            change_pass = conn.extend.microsoft.modify_password(
                user=user_dn, new_password=new_pass, old_password=None
            )

            if change_pass:
                console.print(f"[green][+][/] Changed [yellow]{target}[/] password to [yellow]{new_pass}[/] successfully!\n", highlight=False)
            else:
                console.print(f"[red][!][/] Execution returned [red]False[/], unable to change [yellow]{target}[/] password to [yellow]{new_pass}[/]", highlight=False)
                console.print(
                    "[red][!][/] Probably reasons: \n 1. Your user does not have required permissions (need to have Administrator privileges)\n 2. Domain Policy does not allow changing user password on this way\n 3. The new password is weak for the password policy\n",
                    highlight=False,
                )

        except Exception as error:
            raise error
