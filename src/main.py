from importlib import import_module
from cmd import Cmd
from os import sys, environ
from rich.console import Console
from pathlib import Path
from pkgutil import iter_modules
from shlex import split

from handlers.help_table import help_table
from handlers.profile.create_profile import profile_folder
from handlers.profile.load_profile import select_and_load_profile, current_profile
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
        self.load_modules("modules.privesc")

    def load_modules(self, package_name):
        package = import_module(package_name)
        package_path = str(Path(package.__file__).parent)

        for _, module_name, _ in iter_modules([package_path]):
            if not module_name.startswith('__'):
                full_module_name = f"{package_name}.{module_name}"
                module = import_module(full_module_name)
                
                class_name = ''.join(word.title() for word in module_name.split('_'))
                try:
                    module_class = getattr(module, class_name)
                    self.register_command(module_name, module_class())
                except AttributeError:
                    pass

    def register_command(self, command_name, command_instance):
        def command_handler(inp, *args):
            parts = split(inp)

            if not environ.get('breads_profile'):
                console.print("[red][!][/] You need to load a profile first, use 'load_profile' command\n")
                return
            
            if len(parts) < getattr(command_instance, 'min_args', 0):
                usage_desc = getattr(command_instance, 'usage_desc', "[red][!][/] No usage description definied. Please use the help command.")
                console.print(f"{usage_desc}\n", highlight=False)
                #console.print(f"[red][!][/] Missing required arguments. Expected at least {command_instance.min_args} arguments. Use 'help' command to more details")
            else:
                command_instance.on_login(*parts)

        setattr(self, f"do_{command_name}", command_handler)

    def on_command(self, command_instance, args):
        if getattr(command_instance, 'requires_args', False):
            if not args:
                console.print("[red][!][/] This command requires arguments. Check the requirements in 'help' command")
                return
            
            command_instance.on_login(args)
        else:
            command_instance.on_login()

    def do_create_profile(self, inp):
        profile_folder(inp)

    def do_load_profile(self, inp):
        select_and_load_profile(inp)

    def do_current_profile(self, inp):
        current_profile()

    def do_help(self, inp):
        help_table(inp)

    def do_exit(self, inp):
        console.print("\n[green][+][/] Goodbye! :wave:")
        sys.exit(0)

    def do_banner(self, inp):
        get_banner()

    def emptyline(self):
        pass

BreadsPrompt().cmdloop()