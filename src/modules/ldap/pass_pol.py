from handlers.ldap_connection import LdapHandler

from rich.console import Console
console = Console()

_LOGOFF_NOT_ENFORCED = -9223372036854775808

class PassPol:
    name = "pass-pol"
    desc = "Get the domain password policy"
    module_protocol = ['ldap']
    opsec_safe = True
    multiple_hosts = False
    search_filter = '(objectClass=domainDNS)'
    attributes = ['forceLogoff', 'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength']

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options (self):
        pass

    def on_login(self):
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]

        if res_status:
            console.print("[green][+][/] Password Policy:")

            pass_info = {}
            seen_attributes = set()
            lockout_thresold_printed = False
            force_logoff_printed = False

            for key, value in res_response[0]['attributes'].items():
                if key not in seen_attributes:
                    pass_info[key] = value
                    seen_attributes.add(key)

            lockout_thresold = pass_info.get('lockoutThreshold')
            if lockout_thresold == 0 and not lockout_thresold_printed:
                pass_info['lockoutThreshold'] = '[yellow]0 - Password Spray possibility[/]'
                lockout_thresold_printed = True 

            forced_logoff = pass_info.get('forceLogoff')
            if forced_logoff == _LOGOFF_NOT_ENFORCED and not force_logoff_printed:
                pass_info['forceLogoff'] = "[yellow]0 - forceLogoff is not enforced[/]"
                force_logoff_printed = True

            for attribute, value in pass_info.items():
                console.print(f"[green][+][/] [bright_white]{attribute}: {value}[/]", highlight=False)
        else:
            console.print("[red][!][/] No entries found in the results.")