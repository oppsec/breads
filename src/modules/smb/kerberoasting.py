from impacket.krb5 import constants
from impacket.krb5.asn1 import TGS_REP
from impacket.krb5.types import Principal
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from impacket.smbconnection import SMBConnection
from rich.console import Console
console = Console()

from handlers.smb_connection import SMBConnectionManager
from handlers.ldap_connection import LdapHandler

class Kerberoasting:
    name = "kerberoasting"
    desc = "Search for kerberoasting computers and users"
    module_protocol = ['smb', 'ldap']
    opsec_safe = True
    multiple_hosts = False
    requires_args = True
    min_args = 1
    search_filter = '(&(servicePrincipalName=*)(!(objectCategory=computer)))'
    attributes = 'sAMAccountName'

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self):
        pass

    def get_machine_name(self, dc_ip) -> None:
        ''' Get the machine name thorugh an SMBConnection + getServerName()'''

        smb_manager = SMBConnectionManager()
        smb_connection = smb_manager.get_smb_connection(dc_ip)
        machine_name = smb_connection.getServerName()
        return machine_name
    
    def get_kerberoastable_users(self, dc_ip) -> None:
        ''' Get all kerberoastable users through LDAP query '''
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        users = []

        if res_status:
            if not res_response[0].get('attributes'):  # Access using 'get' to avoid KeyError
                return False
            
            for _key, value in res_response[0]['attributes'].items():
                users.append(value)

        return users

    def on_login(self, con_input):
        if not con_input or len(con_input.split()) < 1:
            console.print("[red]Usage:[/] kerberoasting <target>")
            return
        
        console.print(f'[green][+][/] Target: {self.get_machine_name(con_input)}')

        kerberoastable_users = self.get_kerberoastable_users(con_input)
        if not kerberoastable_users:
            console.print(f'[red][!][/] No kerberoastable users found')
            return  # Exit function if no users found

        console.print(f'[green][+][/] Kerberoastable Users: {kerberoastable_users}')