from typing import Optional, Dict
from rich.console import Console
console = Console()

import ldap3

from handlers.ldap_connection import LdapHandler

# *******************************
# * WORKFLOW
# * 1. Capture username and group desired based on user input
# * 2. Check if specified user exists on the Active Directory
# * 3. Try user password without specifying the old password (Admin privilege is required)
# *******************************

class ChangePassword:
    name = "change-password"
    desc = "Change desired user password"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    user_target = None
    search_filter = None
    requires_args = True
    min_args = 2
    attributes = 'sAMAccountName'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options: Optional[Dict] = module_options

    def options (self):
        pass

    def get_user_dn(self, conn, base_dn, target):
        dn_query = conn.search(base_dn, f'(&(objectClass=user)(sAMAccountName={target}))', attributes=['*'])
        dn_response = dn_query[2]
        return dn_response

    def on_login(self, *args):
        if len(args) != 2:
            console.print("[yellow]Usage:[/] change_password <username> <new_password>", highlight=False)
            return

        target = args[0]
        new_pass = args[1]

        try:
            conn, base_dn = LdapHandler.connection(self)
            console.print(f"[green][+][/] Changing user [yellow]{target}[/] password to [yellow]{new_pass}[/]")

            user_dn = self.get_user_dn(conn, base_dn, target)

            if not user_dn[0]['type'] == 'searchResEntry':
                console.print("[red][!][/] User not found or LDAP search failed.")
                return
            
            encoded_new_password = ('"%s"' % new_pass).encode('utf-16-le')
            console.print(f'[i] \_ Encoded Password (utf-16-le): {encoded_new_password} [/]', highlight=False)
            
            user_dn = user_dn[0]['raw_dn'].decode('utf-8')
            change_pass = ldap3.extend.microsoft.modifyPassword.ad_modify_password(conn, user_dn, new_password=new_pass, old_password=None)

            if(change_pass):
                console.print(f"[green][+][/] Changed [yellow]{target}[/] password to [yellow]{new_pass}[/] successfully!\n", highlight=False)
            else:
                console.print(f"[red][!][/] Execution returned [red]False[/], unable to change [yellow]{target}[/] password to [yellow]{new_pass}[/]", highlight=False)
                console.print(f"[red][!][/] Probably reasons: \n 1. Your user does not have required permissions (need to have Administrator privileges)\n 2. Domain Policy does not allow changing user password on this way\n 3. The new password is weak\n", highlight=False)
            
        except Exception as error:
            raise error