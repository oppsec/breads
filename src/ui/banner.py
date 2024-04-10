from random import choice
from rich.console import Console
console = Console()

def random_tip() -> None:
    tips = [
        "Use 'help' to list all modules", 
        "Create a profile with 'create_profile <name>' command",
        "We support NT hash as authentication method",
        "Change a user password with 'change_password' module",
        "Update your BREADS with 'pipx reinstall breads-ad --python /usr/bin/pytho' command"
    ]

    tip = choice(tips)
    return tip

VERSION = '1.2.4c'

BANNER_FIRE = f"""                           
    )                   (        
 ( /(  (      (     )   )\ )     
 )\()) )(    ))\ ( /(  (()/( (   
((_)\ (()\  /((_))(_))  ((_)))\  
| |(_) ((_)(_)) ((_)_   _| |((_) 
| '_ \| '_|/ -_)/ _` |/ _` |(_-< 
|_.__/|_|  \___|\__,_|\__,_|/__/   

BREADS :: Breaking Active Directory Security :: {VERSION}
TIP: {random_tip()}
"""

def get_banner() -> None:
    ''' Return the banner from the application '''

    color_list = [
        'yellow', 'magenta', 'cyan', 'red', 'blue'
    ]

    color_choice = choice(color_list)
    console.print(f'[{color_choice}]{BANNER_FIRE}[/]', highlight=False)