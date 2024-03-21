from rich.console import Console
console = Console()
from rich.table import Table
from rich import box

def create_table(title, columns, rows, box_type=box.SIMPLE_HEAD):
    table = Table(title=title, show_header=True, highlight=False, leading=True, box=box_type, title_justify="center")
    for column in columns:
        table.add_column(column["title"], style=column["style"])
    for row in rows:
        table.add_row(*row)
    return table

def help_table(inp):
    console = Console()
    user_input = inp.lower()

    if user_input == "":
        columns = [
            {"title": "Protocol", "style": "green"}, 
            {"title": "No. Modules", "style": "green"}, 
            {"title": "Name", "style": "green"}, 
            {"title": "Description", "style": "green"}, 
            {"title": "Usage", "style": "green"}
        ]

        rows = [
            ("LDAP", "25", "---", "---", "---"),
            ("SMB", "2", "---", "---", "---"),
            ("", "", "create_profile", "Ask user input to create a new profile", "create_profile <name>"),
            ("", "", "load_profile", "Ask user input to load a existing profile", "create_profile <name>"),
            ("", "", "banner", "Return BREADS's banner", "banner"),
        ]

        console.print("[yellow][!][/] Use: [yellow]help <protocol_name>[/] to see specific modules. Example: [yellow]help smb[/]\n", highlight=False)

    elif user_input == "ldap":
        columns = [
            {"title": "Protocol", "style": "green"}, 
            {"title": "Name", "style": "white"}, 
            {"title": "Description", "style": "green"}, 
            {"title": "Usage", "style": "white"}, 
            {"title": "Admin Privilege", "style": "white"}
        ]
        
        rows = [
            ("LDAP", "list_dcs", "Get 'dNSHostName' attribute value from all Domain Controllers", "list_dcs", "[red]No[/]"),
            ("LDAP", "users", "Get 'sAMAccountName' attribute value from Users Accounts", "users", "[red]No[/]"),
            ("LDAP", "disabled_accounts", "Get 'sAMAccountName' attribute value from Disabled Accounts", "disabled_accounts", "[red]No[/]"),
            ("LDAP", "whoami", "Get information from targeted used", "whoami <username>", "[red]No[/]"),
            ("LDAP", "admins", "Get all the accounts from domain that has administrator privilege in somewhere", "admins", "[red]No[/]"),
            ("LDAP", "computers", "Get 'sAMAccountName' from all computers", "computers", "[red]No[/]"),
            ("LDAP", "computer", "Get specific computer information", "computer <sAMAccountName>", "[red]No[/]"),
            ("LDAP", "maq", "Get ms-DS-MachineAccountQuota value", "maq", "[red]No[/]"),
            ("LDAP", "obsolete", "Search for computers with obsolete operating systems", "obsolete", "[red]No[/]"),
            ("LDAP", "cpnl", "Find all Users that need to change password on next login", "cpnl", "[red]No[/]"),
            ("LDAP", "groups", "Get 'sAMAccountName' from all groups", "groups", "[red]No[/]"),
            ("LDAP", "trusted_delegation", "Get 'sAMAccountName' from accounts that has 'ms-DS-AllowedToDelegateTo' enabled", "trusted_delegation", "[red]No[/]"),
            ("LDAP", "pass_pol", "Get the domain password policy", "pass_pol", "[red]No[/]"),
            ("LDAP", "adcs", "Get 'dNSHostName' attribute value from all ADCS servers", "adcs", "[red]No[/]"),
            ("LDAP", "add_to_group", "Add desired user to an existent desired group", "add_to_group <username> <group_name>", "[green]Yes[/]"),
            ("LDAP", "change_password", "Change desired user password", "change_password <username> <new_password>", "[green]Yes[/]"),
            ("LDAP", "domain_sid", "Get SID from Domain Controllers", "domain_sid", "[red]No[/]"),
            ("LDAP", "domain_trusts", "Get Domain Trusts", "domain_trusts", "[red]No[/]"),
            ("LDAP", "sid", "Get object information from specified SID", "sid <SID>", "[red]No[/]"),
            ("LDAP", "group", "Get information from the group name specified", "group <group_name>", "[red]No[/]"),
            ("LDAP", "gpos", "List the GPOs registed in the domain", "gpos", "[red]No[/]"),
            ("LDAP", "servers", "Get 'sAMAccountName', 'operatingSystem' and 'dnsHostName' from all Servers", "servers", "[red]No[/]"),
            ("LDAP", "containers", "Get 'name' and 'distinguishedName' from all Containers", "containers", "[red]No[/]"),
            ("LDAP", "un_delegation", "List accounts and computers vulnerable to Unconstrained Delegation", "un_delegation", "[red]No[/]"),
            ("LDAP", "pass_not_req", "List all accounts that does not need an password to authenticate", "pass_not_req", "[red]No[/]"),
        ]

    elif user_input == "smb":
        columns = [
            {"title": "Protocol", "style": "green"}, 
            {"title": "Name", "style": "white"}, 
            {"title": "Description", "style": "green"}, 
            {"title": "Usage", "style": "white"}, 
            {"title": "Admin Privilege", "style": "white"}
        ]

        rows = [
            ("SMB", "get_uac", "Get the UAC value from a specified target", "get_uac <target>", "[red]No[/]"),
            ("SMB", "kerberoasting", "Search for kerberoastable computers and users", "kerberoasting <dc_ip>", "[red]No[/]")
        ]
    else:
        console.print(f"[red][!][/] Unrecognized command: [yellow]help {user_input}[/]. (Available: ldap, smb)\n")
        return
    
    table = create_table("BREADS - Help", columns, rows)
    console.print(table)