from random import choice
from rich.console import Console
console = Console()

def random_tip() -> None:
    tips = [
        "Use 'help' to list all modules", 
        "Create a profile with 'create_profile <name>' command",
        "You can use the user NT hash in the password profile settings",
        "Change a user password with 'change_password' module",
        "Update your BREADS with 'pipx reinstall breads-ad --python /usr/bin/python' command",
        "Use a module without arguments to see the usage description"
    ]

    tip = choice(tips)
    return tip

BANNER_FIRE = f"""                                            
   __                   __  
  / /  _______ ___ ____/ /__
 / _ \/ __/ -_) _ `/ _  (_-<   Breaking Active Directory Security
/_.__/_/  \__/\_,_/\_,_/___/   1.2.5d - @opps3c

TIP: {random_tip()}
"""

def get_banner() -> None:
    ''' Return the banner from the application '''

    color_list = [
        'yellow', 'magenta', 'cyan', 'red', 'blue', 'green', 'blue_violet'
    ]

    color_choice = choice(color_list)
    console.print(f'[{color_choice}]{BANNER_FIRE}[/]', highlight=False)