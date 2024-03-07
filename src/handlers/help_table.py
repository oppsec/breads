from rich.console import Console
console = Console()
from rich.table import Table, Column
from rich import box

def help_table() -> None:
    ''' Return the list of available BREADS modules through Tab's rich class '''

    table = Table(
        title="BREADS - Help", 
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
    table.add_column("Admin Privilege", style="white")

    table.add_row("", "create_profile", "Ask user input to create a new profile", "create_profile <name>", "")
    table.add_row("", "load_profile", "Ask user input to load a existing profile", "load_profile <name>", "")
    table.add_row("", "banner", "Return BREADS's banner", "banner", "")
    table.add_row("LDAP", "list_dcs", "Get 'dNSHostName' attribute value from all Domain Controllers", "list_dcs", "[red]No[/]")
    table.add_row("LDAP", "users", "Get 'sAMAccountName' attribute value from Users Accounts", "users", "[red]No[/]")
    table.add_row("LDAP", "disabled_accounts", "Get 'sAMAccountName' attribute value from Disabled Accounts", "disabled_accounts", "[red]No[/]")
    table.add_row("LDAP", "whoami", "Get information from targeted used", "whoami <username>", "[red]No[/]")
    table.add_row("LDAP", "admins", "Get all the accounts from domain that has administrator privilege in somewhere", "admins", "[red]No[/]")
    table.add_row("LDAP", "computers", "Get 'sAMAccountName' from all computers", "computers", "[red]No[/]")
    table.add_row("LDAP", "maq", "Get ms-DS-MachineAccountQuota value", "maq", "[red]No[/]")
    table.add_row("LDAP", "obsolete", "Search for computers with obsolete operating systems", "obsolete", "[red]No[/]")
    table.add_row("LDAP", "cpnl", "Find all Users that need to change password on next login", "cpnl", "[red]No[/]")
    table.add_row("LDAP", "groups", "Get 'sAMAccountName' from all groups", "groups", "[red]No[/]")
    table.add_row("LDAP", "trusted_delegation", "Get 'sAMAccountName' from accounts that has 'ms-DS-AllowedToDelegateTo' enabled", "trusted_delegation", "[red]No[/]")
    table.add_row("LDAP", "pass_pol", "Get the domain password policy", "pass_pol", "[red]No[/]")
    table.add_row("LDAP", "adcs", "Get 'dNSHostName' attribute value from all ADCS servers", "adcs", "[red]No[/]")
    table.add_row("LDAP", "add_to_group", "Add desired user to an existent desired group", "add_to_group <username> <group_name>", "[green]Yes[/]")
    table.add_row("LDAP", "change_password", "Change desired user password", "change_password <username> <new_password>", "[green]Yes[/]")
    table.add_row("SMB", "get_uac", "Get the UAC value from a specified target", "get_uac <target>", "[red]No[/]")
    table.add_row("SMB", "kerberoasting", "Search for kerberoastable computers and users", "kerberoasting <dc_ip>", "[red]No[/]")

    console.print(table)