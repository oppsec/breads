from rich.table import Table
from rich import box
from rich.console import Console

console = Console()


def create_table(title, columns, rows, box_type=box.SIMPLE_HEAD) -> None:
    """
    title: define the table Title
    columns: create the main column with title parameter
    rows: create the rows to be used by the columns
    """

    table = Table(
        title=title,
        show_header=True,
        highlight=False,
        leading=True,
        box=box_type,
        title_justify="center",
    )
    for column in columns:
        table.add_column(column["title"], style=column["style"])
    for row in rows:
        table.add_row(*row)
    return table


def help_table(inp) -> None:
    """Return the help table based on create_table function structure"""

    console = Console()
    user_input: str = inp.lower()

    if user_input == "":
        columns = [
            {"title": "Target", "style": "green"},
            {"title": "No. Modules", "style": "green"},
            {"title": "Name", "style": "green"},
            {"title": "Description", "style": "green"},
            {"title": "Usage", "style": "green"},
        ]

        rows = [
            ("LDAP", "31", "---", "---", "---"),
            ("SMB", "2", "---", "---", "---"),
            ("PRIVESC", "1", "---", "---", "---"),
            (
                "",
                "",
                "create_profile",
                "Ask user input to create a new profile",
                "create_profile <name>",
            ),
            (
                "",
                "",
                "load_profile",
                "Ask user input to load a existing profile",
                "load_profile <name>",
            ),
            (
                "",
                "",
                "current_profile",
                "Print current loaded profile settings",
                "current_profile",
            ),
            ("", "", "banner", "Return BREADS's banner", "banner"),
        ]

        console.print("\n[yellow]TIP: Use [white]'help <protocol>'[/] to list all protocol modules[/]", highlight=False)

    elif user_input == "ldap":
        columns = [
            {"title": "Protocol", "style": "green"},
            {"title": "Name", "style": "white"},
            {"title": "Description", "style": "green"},
            {"title": "Usage", "style": "white"},
            {"title": "Admin Privilege", "style": "white"},
        ]

        rows = [
            (
                "LDAP",
                "list_dcs",
                "Get 'dNSHostName' attribute value from all Domain Controllers",
                "list_dcs",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "users",
                "Get 'sAMAccountName' attribute value from Users Accounts",
                "users",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "disabled_accounts",
                "Get 'sAMAccountName' attribute value from Disabled Accounts",
                "disabled_accounts",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "whoami",
                "Get information from targeted used",
                "whoami <username>",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "admins",
                "Get all the accounts from domain that has administrator privilege in somewhere",
                "admins",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "computers",
                "Get 'sAMAccountName' from all computers",
                "computers",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "computer",
                "Get specific computer information",
                "computer <sAMAccountName>",
                "[red]No[/]",
            ),
            ("LDAP", "maq", "Get ms-DS-MachineAccountQuota value", "maq", "[red]No[/]"),
            (
                "LDAP",
                "obsolete",
                "Search for computers with obsolete operating systems",
                "obsolete",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "cpnl",
                "Find all Users that need to change password on next login",
                "cpnl",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "groups",
                "Get 'sAMAccountName' from all groups",
                "groups",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "trusted_delegation",
                "Get 'sAMAccountName' from accounts that has 'ms-DS-AllowedToDelegateTo' enabled",
                "trusted_delegation",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "pass_pol",
                "Get the domain password policy",
                "pass_pol",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "adcs",
                "Enumerate ADCS servers and Certificate Templates",
                "adcs",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "add_to_group",
                "Add desired user to an existent desired group",
                "add_to_group <username> <group_name>",
                "[green]Yes[/]",
            ),
            (
                "LDAP",
                "change_password",
                "Change desired user password",
                "change_password <username> <new_password>",
                "[green]Yes[/]",
            ),
            (
                "LDAP",
                "domain_sid",
                "Get SID from Domain Controllers",
                "domain_sid",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "domain_trusts",
                "Get Domain Trusts",
                "domain_trusts",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "sid",
                "Get object information from specified SID",
                "sid <SID>",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "group",
                "Get information from the group name specified",
                "group <group_name>",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "gpos",
                "List the GPOs registed in the domain",
                "gpos",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "servers",
                "Get 'sAMAccountName', 'operatingSystem' and 'dnsHostName' from all Servers",
                "servers",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "containers",
                "Get 'name' and 'distinguishedName' from all Containers",
                "containers",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "un_delegation",
                "List accounts and computers vulnerable to Unconstrained Delegation",
                "un_delegation",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "pass_not_req",
                "List all accounts that does not need an password to authenticate",
                "pass_not_req",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "kerberoasting",
                "Search for kerberoastable computers and users",
                "kerberoasting <dc_ip>",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "aces",
                "Get the nTSecurityDescriptor value from all ACEs and check privileges based on current logged-on user",
                "aces",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "gmsa",
                "Get GMSA accounts passwords",
                "gmsa",
                "[cyan]Preferable[/]",
            ),
            (
                "LDAP",
                "no_pre_auth",
                "Find all users that do not require Kerberos pre-authentication",
                "no_pre_auth",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "search_group",
                "Search for all groups that has specify word on CN attribute",
                "search_group <word>",
                "[red]No[/]",
            ),
            (
                "LDAP",
                "ldapi",
                "Execute custom LDAP queries",
                "ldapi <query> <attributes>",
                "[red]No[/]",
            ),
                        (
                "LDAP",
                "search_computer",
                "Search for all computers that has specify word on CN attribute",
                "search_computer <word>",
                "[red]No[/]",
            ),
        ]

    elif user_input == "smb":
        columns = [
            {"title": "Protocol", "style": "green"},
            {"title": "Name", "style": "white"},
            {"title": "Description", "style": "green"},
            {"title": "Usage", "style": "white"},
            {"title": "Admin Privilege", "style": "white"},
        ]

        rows = [
            (
                "SMB",
                "get_uac",
                "Get the UAC value from a specified target",
                "get_uac <target>",
                "[cyan]Preferable[/]",
            ),
            (
                "SMB",
                "share",
                "Enumerates the available shares of a target computer",
                "share <target>",
                "[cyan]Preferable[/]",
            ),
        ]

    elif user_input == "privesc":
        columns = [
            {"title": "Name", "style": "green"},
            {"title": "Description", "style": "white"},
            {"title": "Requirements", "style": "green"},
            {"title": "Usage", "style": "white"},
            {"title": "Admin Privilege", "style": "green"},
            {"title": "OPSEC Safe?", "style": "green"},
        ]

        rows = [
            (
                "Backup Operator HIVES dump",
                "Abuse Backup Operator privilege to dump the SAM, SECURITY and SYSTEM files",
                "User needs to be a member of the 'Backup Operators' group",
                "backup <target>",
                "[green]Yes[/]",
                "[red]No[/]",
            ),
        ]

    else:
        console.print(
            f"[red][!][/] Unrecognized command: [yellow]help {user_input}[/]. (Available: ldap, smb)\n"
        )
        return

    table = create_table("BREADS - Help", columns, rows)
    console.print(table)
