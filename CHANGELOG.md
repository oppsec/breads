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