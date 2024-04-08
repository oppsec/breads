# 🎉 1.2.4b
- Fixed DCERPCException error in backup module

# 🎉 1.2.4a
- Added new 1 module:
  - New module (ldap): 'ldapi' (Execute custom LDAP queries)
    - Usages exemple: 
      - `ldapi (objectClass=domainDNS) dc`
      - `ldapi (objectClass=domainDNS) dc,systemFlags`
      - `ldapi (objectClass=domainDNS) *`
- Added new command: 'current_profile' (Print current loaded profile settings)

<br><br>

# 🎉 1.2.4
- Added new module category:
  - Privesc: Modules designed to abuse a vulnerability or privilege
    - backup: Abuse Backup Operator privilege to dump the SAM, SECURITY and SYSTEM files
- Removed unecessary code from get_uac module
- Improved 'memberOf', 'member' attribue value response (helpers/manager/list_attribute_handler)
- Minor changes in other modules
- Added 'description' attribute to 'group' module

<br><br>

# 🎉 1.2.3c
- Added new 2 module:
  - New module: 'no_pre_auth' (Find all users that do not require Kerberos pre-authentication)
  - New module: 'search_group' (Search for all groups that has specify word on CN attribute)

<br><br>

# 🎉 1.2.3b
- Now LDAP, SMB (and RPC) modules support NTLM hash as password

<br><br>

# 🎉 1.2.3a
- Improved 'aces' module
- Minor changes in create and load profile modules
- Fixed information confliting when interacting with subdomain (ex: internal.example.com / example.com)
- Fixed SSL error when LDAPS is not required

<br><br>

# 🎉 1.2.3
- Added new 2 module:
  - New module: 'aces' (Get the nTSecurityDescriptor value from all ACEs and check privileges based on current logged-on user)
  - New module: 'gmsa' (Get GMSA accounts passwords)
- Added 'servicePrincipalName' attribute in whoami module
- Added gmsa blob translator (src/helpers/gmsa_blob)
- Minor changes in domain_trusts and change_password

<br><br>

# 🎉 1.2.2
- Added new 1 new module:
  - New module: 'share' (Enumerate the shares available from a targeted computer)
- Moved 'kerberoasting' module to LDAP

<br><br>

# 🎉 1.2.1
- Added new 4 modules
  - New module: 'gpos' (List the GPOs registed in the domain)
  - New module: 'servers' (Get 'sAMAccountName', 'operatingSystem' and 'dnsHostName' from all Servers)
  - New module: 'containers' (Get 'name' and 'distinguishedName' from all Containers)
  - New module: 'pass_not_req' (List all accounts that does not need an password to authenticate)
- Improved module 'obsolete' output
- Improved module 'kerberoasting' LDAP query
- Updated 'domain_trusts' output message

<br><br>

# 🎉 1.2.0a
- Filtered results for whoami command ('description', 'memberOf', 'userAccountControl', 'badPwdCount', 'lastLogoff', 'lastLogon', 'objectSid', 'adminCount', 'accountExpires', 'sAMAccountName')
- Changed the way and colors of the information got printed
- Fixed bug in kerberoasting module
- Improved SID objectClass type identification

<br><br>

# 🎉 1.2.0
- Fixed bugs on 'change_password' module
- New module: 'group'
- New module: 'sid'
- It is possible to add a user to a group or also extract information from the group that contains spaces in the name using ' ('Domain Admins'). Anyway, you can also use % to represent space.

<br><br>

# 🎉 1.1.9a
- New module: 'domain_trusts'
- New module: 'computer <target>'
- New module: 'domain_sid'
- Added SID translator (handlers/sid_translate.py)
- Now to add a member to a group that have spaces on the name, you need to use % as the space, for example: Domain%Admins (if we use _ for example, we cannot add a user for a group with _ in the name, like IIS_IUSRS)
- Improved help command (help, help <protocol_name>)
- Module 'kerberoasting' now return kerberoastable user TGS

<br><br>

# 🎉 1.1.9
- New module: `change_password <username> <new_password>`
- Added tab "Admin Privileges" to help table

<br><br>

# 🎉 1.1.8a
- Removed 'list_adcs' from help command (renamed to adcs)
- Added 'add_to_group' module to help command

<br><br>

# 🎉 1.1.8
- Changed MAQ LDAP query from (objectClass=\*) to (objectClass=domainDNS)
- Renamed maq_account_quota to just maq
- Removed unecessary python-ldap library from maq.py (old maq_account_quota.py)
- Added 'pass_pol' (Password Policy) module
- Minor changes on 'help' command
- Fixed no profile loaded handling
- Added 'kerberoasting' module (not finished yet)
- Added 'adcs' module

<br><br>

# 🎉 1.1.7
- Improved ldap_connection.py code
- Improved attributes reading code
- Added missing module "trusted_delegation" to help command
- Changed commands name
  - list_users -> users
  - list_groups -> groups
  - administrators -> admins
- Fixed 'whoami' module
- Improved 'maq_account_quota' module through search_scope=ldap.SCOPE_BASE
- New module: 'add_to_group <username> <group_name>'
- Started using 'ldap3' library instead of 'python-ldap'
- Fixed 'get_uac' module

<br><br>

# 🎉 1.1.6b
- Added 'list_groups' module

<br><br>

# 🎉 1.1.6
- Module 'list_adcs' not being recognized as module
- Fixed no support to SSL/TLS LDAP servers
- Changed all attributes from 'computers.py' just to 'dnsHostName'
- Module 'maq_account_quota' asking for attributes
- Added 'cpnl' (Change Password on Next Login) module

<br><br>

### ⚠️ 2/24/24
- Fixed PosixPath problem (added str(Path) on main.py)
- Fixed error when creating profile (write() and dump() does not support string)

<br><br>

# 🎉 1.1.5
- Moved from inferigang/breads to oppsec/breads
- Added support to SMB protocol
- Improved all the code

<br><br>

# Older Releases

- https://github.com/inferigang/breads/blob/main/CHANGELOG.md
