#!/usr/bin/python

DOCUMENTATION = '''
---
module: eh_restartSystem
version_added:
short_description: restarts the system by screenscraping
idempotent:  Yes.  Can be ran multiple times and only executes if needed.
description:
options:

'''

#from Extrahop import Extrahop
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
    eda = Extrahop()

    # Start the restart update process
    s = requests.Session()
    s.headers.update({'Referer': LOGIN_PATH,
                      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'})
    # Supress InsecureRequestWarning errors

    # Login to admin page
    rsp = s.get(LOGIN_PATH, verify=False)
    token = rsp.cookies['csrftoken']
    login_params = {'csrfmiddlewaretoken': token,
                    'next': '/admin/',
                    'username': username,
                    'password': passwd}
    s.headers.update({'Referer': LOGIN_PATH})
    # Send login data
    loginrsp = s.post(LOGIN_PATH,
                             data=login_params,
                             verify=False)

    token = loginrsp.cookies['csrftoken'] or rsp.cookies['extrahop_csrftoken']

    p = re.compile('(<h1>Administration<\/h1>|<title>ExtraHop Administration</title>)',re.IGNORECASE)
    # Check if we loaded the admin page
    match = p.search(loginrsp.text)

    if (not match):
        # We did not load the Admin page.  Fail gracefully
        module.fail_json(msg="Unable to Login")

    # Loaded the Admin Page.  Let's go to restart
    rsp = s.get(RESTART_PATH)
    token = rsp.cookies['csrftoken'] or rsp.cookies['extrahop_csrftoken']

    # Loaded the restart Page.  Let's send the data!
    s.headers.update({'Referer':RESTART_PATH})
    restart_params = {'csrfmiddlewaretoken': token}
    restart_rsp = s.post(RESTART_PATH,data=restart_params, verify=False)

    module.fail_json(msg=str(restart_rsp))

class Extrahop(object):
    '''
    Utility and generic superclass for Extrahop platforms and operations.
    '''
    def __init__(self):
        '''
        Constructor
        '''
        pass

    def check_for_response(self,eda):
        '''
        Check for timeouts and service startup.  This function should be used in a polling cycle to continuously check every X amount of time
        returns:
            True if system is responding
            False if system is not responding or still starting up
        '''
        # Attempt HTTP connection to main page.
        try:
            rsp = requests.get('https://' + eda + '/extrahop/ping/', verify=False)
        except requests.exceptions.ConnectionError:
            # Timeout.  System is not responding
            return False
        if rsp.status_code != 200:
            # Server error.  Usually due to service startup or shutdown.
            return False
        else:
            return True


    def web_logon(self,httpsession,user,passwd):
        '''
        Logon to HTTP Web using requests.Session() object.
        returns:
          dict("session": requests.Session()
               "statusCode": int
               "msg": str
               }
        '''
        pass
from ansible.module_utils.basic import *
main()
