#!/usr/bin/python

DOCUMENTATION = '''
---
module: eh_restartSystem
version_added: 6.2.6 (also validated on 7.3.3)
short_description: restarts the system by screenscraping
idempotent:  Yes.  Can be ran multiple times and only executes if needed.
description:
    - Restarts the extrahop system remotely by grabbing the csrftoken cookie from the login session, and posting restart command
options:
    eda:
        descripton: the hostname of the EDA targetted
        required: True
    username:
        description:
            - User to create the API Key for.  Must be an existing admin user
        required: True
    passwd:
        description:
            - Password for defined user.
        required: True
'''

import re
import requests
import time
import requests.packages.urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.packages.urllib3.exceptions import SNIMissingWarning
from requests.packages.urllib3.exceptions import InsecurePlatformWarning

def main():
    module = AnsibleModule(
        argument_spec = dict(
            #login
            eda = dict(required=True,type='str'),
            username = dict(required=True),
            passwd = dict(required=True)
        ),
    supports_check_mode = False,
    )

    args = module.params
    eda = module.params['eda']
    username = args["username"]
    passwd = args["passwd"]

    LOGIN_PATH = "https://" + eda + "/admin/login/"
    RESTART_PATH = "https://" + eda + "/admin/restart/module/system"

    # Determine current restart for idempotence
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    s = requests.Session()

    # Start the restart update process
    s = requests.Session()
    s.headers.update({'Referer': LOGIN_PATH,
                      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'})
    # Supress InsecureRequestWarning errors

    # Login to admin page
    rsp = s.get(LOGIN_PATH, verify=False)

    try:
        token = rsp.cookies['csrftoken']
    except KeyError:
        token = rsp.cookies['extrahop_csrftoken']

    login_params = {'csrfmiddlewaretoken': token,
                    'next': '/admin/',
                    'username': username,
                    'password': passwd}
    s.headers.update({'Referer': LOGIN_PATH})
    # Send login data
    loginrsp = s.post(LOGIN_PATH,
                             data=login_params,
                             verify=False)

    p = re.compile('(<h1>Administration<\/h1>|<title>ExtraHop Administration</title>)',re.IGNORECASE)
    # Check if we loaded the admin page
    match = p.search(loginrsp.text)

    if (not match):
        # We did not load the Admin page.  Fail gracefully
        module.fail_json(msg="Unable to Login")

    # Loaded the Admin Page.  Let's go to restart
    rsp = s.get(RESTART_PATH)
    try:
        token = rsp.cookies['csrftoken']
    except KeyError:
        token = rsp.cookies['extrahop_csrftoken']
    # Loaded the restart Page.  Let's send the data!
    s.headers.update({'Referer':RESTART_PATH})
    restart_params = {'csrfmiddlewaretoken': token}
    restart_rsp = s.post(RESTART_PATH,data=restart_params, verify=False)

    if restart_rsp.status_code != 200:
            module.fail_json(msg=str(restart_rsp))

    module.exit_json(changed=True)

from ansible.module_utils.basic import *
main()
