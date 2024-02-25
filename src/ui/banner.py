from random import choice
from rich import print

VERSION = '1.1.6'
BANNER = f'''
BREADS - Breaking Active Directory Security - {VERSION}
'''

def get_banner() -> None:
    ''' Return the banner from the application '''

    color_list = [
        'yellow', 'magenta', 'cyan', 'red', 'blue'
    ]

    color_choice = choice(color_list)
    print(f'[{color_choice}]{BANNER}[/]')