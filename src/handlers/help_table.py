from rich.console import Console
console = Console()
from rich.table import Table, Column
from rich import box

def help_table() -> None:
    ''' Return the list of available modules through Tab's rich module '''

    table = Table(
        title="BREADS - Modules List", 
        caption='All available modules for different protocols and profile management',  
        show_header=True,
        highlight=False,
        leading=True,
        box=box.SIMPLE_HEAD,
        title_justify="center"
    )

    table.add_column("Protocol", style="green")
    table.add_column("Name", style="white")
    table.add_column("Description", style="green")
    table.add_column("Usage", style="white")

    table.add_row("", "create_profile", "Ask user input to create a new profile", "create_profile <name>")
    table.add_row("", "load_profile", "Ask user input to load a existing profile", "load_profile <name>")
    table.add_row("", "banner", "Return BREADS's banner", "banner")
    table.add_row("LDAP", "list_dcs", "Get 'dNSHostName' attribute value from all Domain Controllers", "list_dcs")
    table.add_row("LDAP", "users", "Get 'sAMAccountName' attribute value from Users Accounts", "users")
    table.add_row("LDAP", "disabled_accounts", "Get 'sAMAccountName' attribute value from Disabled Accounts", "disabled_accounts")
    table.add_row("LDAP", "whoami", "Get information from targeted used", "whoami <username>")
    table.add_row("LDAP", "list_adcs", "Get attributes from ADCS server", "list_adcs")
    table.add_row("LDAP", "admins", "Get all the accounts from domain that has administrator privilege in somewhere", "administrators")
    table.add_row("LDAP", "computers", "Get 'sAMAccountName' from all computers", "computers")
    table.add_row("LDAP", "maq_account_quota", "Get ms-DS-MachineAccountQuota value", "maq_account_quota")
    table.add_row("LDAP", "obsolete", "Search for computers with obsolete operating systems", "obsolete")
    table.add_row("LDAP", "cpnl", "Find all Users that need to change password on next login", "cpnl")
    table.add_row("LDAP", "groups", "Get 'sAMAccountName' from all groups", "groups")
    table.add_row("LDAP", "trusted_delegation", "Get 'sAMAccountName' from accounts that has 'ms-DS-AllowedToDelegateTo' enabled", "trusted_delegation")
    table.add_row("SMB", "get_uac", "Get the UAC value from a specified target (Adminstrator privilege is required)", "get_uac <target>")

    console.print(table)