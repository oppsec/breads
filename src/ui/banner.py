from random import choice
from rich.console import Console
console = Console()

VERSION = '1.2.2'

BANNER_FIRE = f"""                           
    )                   (        
 ( /(  (      (     )   )\ )     
 )\()) )(    ))\ ( /(  (()/( (   
((_)\ (()\  /((_))(_))  ((_)))\  
| |(_) ((_)(_)) ((_)_   _| |((_) 
| '_ \| '_|/ -_)/ _` |/ _` |(_-< 
|_.__/|_|  \___|\__,_|\__,_|/__/   

BREADS :: Breaking Active Directory Security :: {VERSION}
TIP: Use 'help' to list all modules
"""

def get_banner() -> None:
    ''' Return the banner from the application '''

    color_list = [
        'yellow', 'magenta', 'cyan', 'red', 'blue'
    ]

    color_choice = choice(color_list)
    console.print(f'[{color_choice}]{BANNER_FIRE}[/]', highlight=False)