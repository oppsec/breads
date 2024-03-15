# 🎉 1.2.0a
- Filtered results for whoami command ('description', 'memberOf', 'userAccountControl', 'badPwdCount', 'lastLogoff', 'lastLogon', 'objectSid', 'adminCount', 'accountExpires', 'sAMAccountName')
- Changed the way and colors of the information got printed
- Fixed bug in kerberoasting module
- Improved SID objectClass type identification

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
- New module: 'change_password <username> <new_password>'
- Added tab "Admin Privileges" to help table

<br><br>

# 🎉 1.1.8a
- Removed 'list_adcs' from help command (renamed to adcs)
- Added 'add_to_group' module to help command

<br><br>

# 🎉 1.1.8
- Changed MAQ LDAP query from (objectClass=*) to (objectClass=domainDNS)
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