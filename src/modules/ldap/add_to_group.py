from ldap3 import MODIFY_ADD
from typing import Optional, Dict
from rich.console import Console
console = Console()

from handlers.ldap_connection import LdapHandler

# *******************************
# * WORKFLOW
# * 1. Capture username and group desired based on user input
# * 2. Check if specified user exists on the Active Directory
# * 3. Check if specified group exists on the Active Directory
# * 4. Trying to add specified user to the desired group (expecting that the user have permission to do that)
# *******************************

class AddToGroup:
    name = "add-to-group"
    desc = "Add user to a desired group from the Active Directory environment"
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
    
    def get_group_dn(self, conn, base_dn, group):
        dn_query = conn.search(base_dn, f'(&(objectClass=group)(cn={group}))', attributes=['*'])
        dn_response = dn_query[2]
        return dn_response

    def on_login(self, *args):
        console.print("[yellow]WARNING:[/] The space between the group name need to be replaced with '%'. Example: [green]Domain%Admins[/]. Or you can use 'Domain Admins'\n")

        if len(args) != 2:
            console.print("[yellow]Usage:[/] add_to_group <username> <group_name>", highlight=False)
            return

        target = args[0]
        group = args[1]
        group = group.replace("%", " ")

        try:
            conn, base_dn = LdapHandler.connection(self)
            console.print(f"[green][+][/] Adding user [yellow]{target}[/] to group [cyan]{group}[/]")

            user_dn = self.get_user_dn(conn, base_dn, target)
            group_dn = self.get_group_dn(conn, base_dn, group)

            if not user_dn[0]['type'] == 'searchResEntry':
                console.print("[red][!][/] User not found or LDAP search failed.")
                return
            
            if not group_dn[0]['type'] == 'searchResEntry':
                console.print("[red][!][/] Group not found or LDAP search failed.")
                return
            
            user_dn = user_dn[0]['raw_dn'].decode('utf-8')
            group_dn = group_dn[0]['raw_dn'].decode('utf-8')

            add_to_group = conn.modify(group_dn, {
                "member": [(MODIFY_ADD, [user_dn])]
            })

            add_to_group_response = add_to_group[1]['description']
            console.print(f'[yellow][!][/] Operation status: [b]{add_to_group_response}[/b]')

            permissions = {
                'insufficientAccessRights': f'[red][!][/] User [yellow]{target}[/] has not permission to add [yellow]{target}[/] to [cyan]{group}[/] group\n',
                'entryAlreadyExists': f'[red][!][/] User [yellow]{target}[/] is already a member of [cyan]{group}[/] group\n',
                'success': f'[green][+][/] User {target} added to group {group} successfully!\n'
            }

            console.print(permissions.get(add_to_group_response, "[red][!][/] Something strange happened, please check 'Operation status'\n"))

        except Exception as e:
            console.print(f"[red][!][/] Error: {e}")