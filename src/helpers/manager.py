from re import search
from rich.console import Console

console = Console()

def list_attribute_handler(attribute, value):
    """ Filter and print attributes list values in more readable way """
    if attribute in ["memberOf", "member", "servicePrincipalName", "objectClass"]:
        console.print(f" - [cyan]{attribute}[/]:", highlight=False)
        
        for group in value:
            cn_value = search(r"CN=([^,]+)", group)
            if cn_value:
                console.print(f"   - {cn_value.group(1)}", highlight=False)
            else:
                console.print(f"   - {group}", highlight=False)
    else:
        console.print(f" - [cyan]{attribute}[/]: {value}", highlight=False)