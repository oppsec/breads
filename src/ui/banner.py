from random import choice
from rich.console import Console
console = Console()

VERSION = '1.1.7'
BANNER = f'''
BREADS :: Breaking Active Directory Security :: {VERSION}
TIP: Use 'help' to list all modules
'''

def get_banner() -> None:
    ''' Return the banner from the application '''

    color_list = [
        'yellow', 'magenta', 'cyan', 'red', 'blue'
    ]

    color_choice = choice(color_list)
    console.print(f'[{color_choice}]{BANNER}[/]', highlight=False)