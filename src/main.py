import importlib
from cmd import Cmd
from os import sys
from rich.console import Console
from pathlib import Path
from pkgutil import iter_modules

from handlers.help_table import help_table
from handlers.profile.create_profile import profile_folder
from handlers.profile.load_profile import select_and_load_profile
from ui.banner import get_banner

console = Console()

class BreadsPrompt(Cmd):
    prompt = "breads # "
    intro = get_banner()

    def __init__(self):
        super().__init__()
        self.commands = {}
        self.load_modules("modules.ldap")
        self.load_modules("modules.smb")

    def load_modules(self, package_name):
        package = importlib.import_module(package_name)
        package_path = str(Path(package.__file__).parent)

        for _, module_name, _ in iter_modules([package_path]):
            if not module_name.startswith('__'):
                full_module_name = f"{package_name}.{module_name}"
                module = importlib.import_module(full_module_name)
                
                class_name = ''.join(word.title() for word in module_name.split('_'))
                try:
                    module_class = getattr(module, class_name)
                    self.register_command(module_name, module_class())
                except AttributeError:
                    pass

    def register_command(self, command_name, command_instance):
        setattr(self, f"do_{command_name}", lambda inp, *args: self.on_command(command_instance, inp))

    def on_command(self, command_instance, args):
        if getattr(command_instance, 'requires_args', False):
            if not args:
                console.print("[red][!][/] [bright_white]This command requires arguments. Check the requirements in 'help' command[/]")
                return
            command_instance.on_login(args)
        else:
            command_instance.on_login()

    def do_create_profile(self, inp):
        profile_folder(inp)

    def do_load_profile(self, inp):
        select_and_load_profile(inp)

    def do_help(self, inp):
        help_table()

    def do_exit(self, inp):
        console.log("[red][!] Exiting... [/]")
        sys.exit(0)

    def do_banner(self, inp):
        get_banner()

    def emptyline(self):
        pass

BreadsPrompt().cmdloop()