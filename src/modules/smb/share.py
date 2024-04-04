from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.smbconnection import SMBConnection
from rich.console import Console

from handlers.profile.helper import load_profile_settings

console = Console()


class Share:
    name = "share"
    desc = "Enumerates the available shares of a target computer"
    module_protocol = ["smb"]
    opsec_safe = True
    multiple_hosts = False
    require_args = True
    min_args = 1

    def get_rpc_connection(self, target_ip: str):

        username, password, domain = load_profile_settings(self)

        if len(password) == 32 and all(c in "0123456789abcdefABCDEF" for c in password):
            use_ntlmv2_hash = True
        else:
            use_ntlmv2_hash = False

        rpc_string = r"ncacn_np:%s[\pipe\srvsvc]" % target_ip
        transport_obj = transport.DCERPCTransportFactory(rpc_string)

        if use_ntlmv2_hash:
            smb_connection = SMBConnection(target_ip, target_ip)
            lmhash = 'aad3b435b51404eeaad3b435b51404ee'
            nthash = password
            smb_connection.login(username, '', domain=domain, lmhash=lmhash, nthash=nthash)
            transport_obj.set_smb_connection(smb_connection)
        else:
            transport_obj.set_credentials(username, password, domain)

        try:
            transport_obj.connect()
            console.print("[green][+][/] RPC connection established")
            dce = transport_obj.DCERPC_class(transport_obj)
            dce.bind(srvs.MSRPC_UUID_SRVS)
            return dce

        except DCERPCException as error:
            console.print(f"[red][!][/] Error estabilishing RPC connection: {error}")
            return None

    def on_login(self, target: str):
        if not target or len(target.split()) < 1:
            console.print("[red]Usage:[/] share <target_ip>")
            return

        target = target.split()[0]

        try:
            rpc_connection = self.get_rpc_connection(target)
            resp = srvs.hNetrShareEnum(rpc_connection, 2)

            if rpc_connection is None:
                console.print(
                    f"[red][!][/] Unable to estabilish RPC connection with {target}"
                )
                return

            if resp is None or resp["ErrorCode"] != 0:
                console.print("[red][!][/] Error enumerating share information")
                return

            console.print(f"[green][+][/] Enumerating shares from [yellow]{target}[/]:")

            for share in resp["InfoStruct"]["ShareInfo"]["Level2"]["Buffer"]:
                share_name = share["shi2_netname"][:-1]
                share_remark = share["shi2_remark"][:-1]
                share_path = share["shi2_path"][:-1]
                share_permissions = share["shi2_permissions"]

                console.print(
                    f" [cyan]-[/] {share_name} - [yellow]{share_remark}[/] - {share_path} - [yellow]{share_permissions}[/]",
                    highlight=False,
                )

        except Exception as error:
            console.print(
                f"[red][!][/] Error during share enumeration process: {error}"
            )
            # raise error
