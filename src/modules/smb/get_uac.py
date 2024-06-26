from rich.console import Console
from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations
from handlers.smb_connection import SMBConnectionManager 

console = Console()

class GetUac:
    name = "get_uac"
    desc = "Check the UAC status"
    module_protocol = ['smb']
    opsec_safe = True
    multiple_hosts = False
    requires_args = True
    min_args = 1
    usage_desc = "[yellow]Usage:[/] get_uac <ip_address> or <computer.domain> (ex: get_uac 192.168.20.1 or get_uac computer.local)"

    def on_login(self, con_input):

        target = con_input.split()[0]
        smb_manager = SMBConnectionManager()
        smb_connection = smb_manager.get_smb_connection(target) 

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
               console.print("- [cyan]UAC Status[/]: 1 [green](Enabled)[/]", highlight=False)
            elif uac_value == 0:
                console.print("- [cyan]UAC Status[/]: 0 [red](Disabled)[/]", highlight=False)

            rrp.hBaseRegCloseKey(remoteOps._RemoteOperations__rrp, key_handle)
            remoteOps.finish()

        except Exception as e:
            console.print(f"[red][!][/] Error during UAC check: {e}")