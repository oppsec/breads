from rich.console import Console
from rich.table import Table

def help_table() -> None:

    table = Table(
        title="BREADS - Commands List", 
        caption='All available commands for different protocols and profile management',  
        show_lines=True, 
        show_header=True,
        highlight=False,
        leading=True
    )

    table.add_column("Protocol", style="green")
    table.add_column("Name", style="white")
    table.add_column("Description", style="green")
    table.add_column("Autocomplete?", style="yellow")
    table.add_column("Usage", style="white")

    table.add_row("N/A", "create_profile", "Ask user input to create a new profile", "Yes", "create_profile <name>")
    table.add_row("N/A", "load_profile", "Ask user input to load a existing profile", "Yes", "load_profile <name>")
    table.add_row("N/A", "banner", "Return the banner from the application", "Yes", "banner")
    table.add_row("LDAP", "list_dcs", "Retrieve 'dNSHostName' from all Domain Controllers", "No", "N/A")
    table.add_row("LDAP", "list_users", "Retrieve 'sAMAccountName' from all users", "No", "N/A")
    table.add_row("LDAP", "disabled_accounts", "Retrieve 'sAMAccountName' from all the disabled accounts", "No", "N/A")
    table.add_row("LDAP", "whoami", "Extract information from a desired account through user input", "No", "whoami <username>")
    table.add_row("LDAP", "adcs", "Retrieve 'dNSHostName', 'cn', 'msPKI-Enrollment-Servers  from all ADCS computers", "No", "N/A")
    table.add_row("LDAP", "administrators", "Get all the accounts from domain that has administrator privilege in somewhere", "No", "N/A")
    table.add_row("LDAP", "computers", "Return all the computers that can be located on the environmen", "No", "N/A")
    table.add_row("LDAP", "maq_account_quota", "Get the Macchine Account Quota value domain-level attribute", "No", "N/A")
    table.add_row("LDAP", "obsolete", "Search for obsolete operating systems installed on computers and get 'dNSHostName', 'operatingSystem' from target", "No", "N/A")
    table.add_row("SMB", "get_uac", "Get the UAC value from a specified target", "No", "get_uac <target>")

    console = Console()
    console.print(table)