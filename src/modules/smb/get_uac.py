from handlers.smb_connection import SMBConnectionManager 
from rich.console import Console
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations

console = Console()

class GetUac:
    name = "get_uac"
    desc = "Check the UAC status"
    module_protocol = ['smb']
    opsec_safe = True
    multiple_hosts = False
    requires_args = True

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self):
        pass

    def on_login(self, con_input):
        if not con_input or len(con_input.split()) < 1:
            console.print("[red]Usage:[/] get_uac <target>")
            return

        target = con_input.split()[0]
        smb_manager = SMBConnectionManager()
        smb_connection = smb_manager.get_smb_connection(target=target) 
        if smb_connection is None:
            console.print("[red][!][/] Unable to establish SMB connection.")
            return

        try:
            remoteOps = RemoteOperations(smb_connection, False)
            remoteOps.enableRegistry()

            rrp_answer = rrp.hOpenLocalMachine(remoteOps._RemoteOperations__rrp)
            reg_handle = rrp_answer["phKey"]
            rrp_answer = rrp.hBaseRegOpenKey(
                remoteOps._RemoteOperations__rrp,
                reg_handle,
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
            )
            key_handle = rrp_answer["phkResult"]
            _data_type, uac_value = rrp.hBaseRegQueryValue(remoteOps._RemoteOperations__rrp, key_handle, "EnableLUA")

            if uac_value == 1:
               console.print("[green][+][/] [bright_white]UAC Status: 1 [green](UAC Enabled)[/]", highlight=False)
            elif uac_value == 0:
                console.print("[green][+][/] [bright_white]UAC Status: 0 [yellow](UAC Disabled)[/]", highlight=False)

            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, key_handle)
            remoteOps.finish()

        except Exception as e:
            console.print(f"[red][!][/] Error during UAC check: {e}")