from ldap.controls import SimplePagedResultsControl
import ldap
from rich.progress import Progress
from rich import print
from pathlib import Path
import json

from handlers.profile.helper import get_current_profile, BREADS_FOLDER
BREADS_FOLDER = Path(BREADS_FOLDER)

class Connection:
    def __init__(self):
        self.domain = None
        self.password = ""
        self.username = ""
        self.hostname = ""

    def ldap_con(self, search_filter, domain, hostname, username, password):
        page_size = 100
        self.search_filter = search_filter
        self.domain = domain
        self.hostname = hostname
        self.username = username
        self.password = password

        if get_current_profile() == 'None':
            print("[red][!][/] You need to load a profile first, use 'load_profile' command")
            return []
        
        settings_json_file = f"{BREADS_FOLDER}/{get_current_profile()}/settings.json"

        with open(settings_json_file, 'r') as settings_file:
            data = json.load(settings_file)

            username = data['username']
            hostname = data['host']
            password = data['password']

            ldap_uri = f'ldap://{hostname}'

            base_dn = username.split('/')[0]
            domain = base_dn
            username = f"{username.split('/')[1]}@{base_dn}"
            base_dn = "DC=" + ",DC=".join(base_dn.split("."))

            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                    
            connect = ldap.initialize(ldap_uri)
            connect.set_option(ldap.OPT_REFERRALS, 0)
            connect.simple_bind_s(username, password)

            search_scope = ldap.SCOPE_SUBTREE

            total_results = []
            req_ctrl = SimplePagedResultsControl(True, size=page_size, cookie='')

            with Progress() as progress:
                task = progress.add_task("[cyan][*][/] [bright_white]Executing command[/]", total=100)

                while not progress.finished:
                    progress.update(task, advance=10)

                    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
                    
                    connect = ldap.initialize(ldap_uri)
                    connect.set_option(ldap.OPT_REFERRALS, 0)
                    connect.simple_bind_s(username, password)

                    search_scope = ldap.SCOPE_SUBTREE

                    try:
                        total_results = []
                        req_ctrl = SimplePagedResultsControl(criticality=True, size=page_size, cookie='')

                        while True:
                            query = connect.search_ext(base_dn, search_scope, search_filter, serverctrls=[req_ctrl])
                            
                            rtype, rdata, rmsgid, serverctrls = connect.result3(query)
                            total_results.extend(rdata)

                            pctrls = [c for c in serverctrls if c.controlType == SimplePagedResultsControl.controlType]
                            if pctrls:
                                if pctrls[0].cookie:
                                    req_ctrl.cookie = pctrls[0].cookie
                                else:
                                    break
                            else:
                                break

                        progress.update(task, advance=40)
                        return total_results
                    
                    except ldap.LDAPError as error:
                        print(f"[red][!][/] [bright_white]LDAP Error: {error}[/]")
                        return []
                    
                    finally:
                        connect.unbind_s()
                        progress.update(task, advance=50)