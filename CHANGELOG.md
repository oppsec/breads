# 1.1.7
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

# 1.1.6b
- Added 'list_groups' module

# 1.1.6
- Module 'list_adcs' not being recognized as module
- Fixed no support to SSL/TLS LDAP servers
- Changed all attributes from 'computers.py' just to 'dnsHostName'
- Module 'maq_account_quota' asking for attributes
- Added 'cpnl' (Change Password on Next Login) module

### 2/24/24
- Fixed PosixPath problem (added str(Path) on main.py)
- Fixed error when creating profile (write() and dump() does not support string)

# 1.1.5
- Moved from inferigang/breads to oppsec/breads
- Added support to SMB protocol
- Improved all the code