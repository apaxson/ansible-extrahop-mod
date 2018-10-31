#!/usr/bin/python
# from __builtin__ import None
# from __builtin__ import None

DOCUMENTATION = '''
---
module: eh_analysis_priorities
version_added:
short_description: Manage extrahop analysis priorities groups
description:
    - Allow adding and removing device groups to/from the extrahop analysis priorities list
options:
    eda:
        descripton: the hostname of the EDA targetted
        required: True
    apiKey:
        description: the API key to interact with the rest API
        required: True
    state:
        description:
            - Action of whitelist module
                - assigned/unassigned
        required: True

    isMemberOf:
        description:
            - This can either be a list of specific group names, or "any" to include devices of any defined group.  Group names can be partial for multiple matches
              i.e. 'Citrix" will include 'Citrix Servers', 'Citrix Brokers', and 'Citrix StoreFront'
        required:  True


Example:
- name: Whitelist Devices
  eh_whitelist:
    eda: "{{ inventory_hostname }}"
    apiKey: "{{ api.key }}"
    state: "assigned"
    isMemberOf:
        - any

'''
import re
import json

import_fail = False
try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.packages.urllib3.exceptions import SNIMissingWarning
    from requests.packages.urllib3.exceptions import InsecurePlatformWarning
    import requests.packages
except:
    import_fail = True

from ansible.module_utils.basic import AnsibleModule

ANALYSIS_PATH='/api/v1/analysispriority/config/0'

def getDeviceGroupIdsFromGroupName(eda,apikey,httpsession,groupName, type):
    # Check if this is a group ID or a group Name
    httpsession.headers.update({'Authorization': 'ExtraHop apikey='+apikey})
    groupIds = []

    if type == "device":
        uri = 'https://'+eda+'/api/v1/devicegroups?all=false&name='+groupName
        rsp = httpsession.get(uri, verify=False)
        if rsp.status_code !=200:
            return False, "URI: " + uri + " returned Status Code: " + str(rsp.status_code) + " " + rsp.text
        groups = json.loads(rsp.text)
        for group in groups:
            groupIds.append(group["id"])
    elif type == "activity":
        uri = 'https://'+eda+'/api/v1/activitygroups'
        rsp = httpsession.get(uri, verify=False)
        if rsp.status_code !=200:
            return False, "URI: " + uri + " returned Status Code: " + str(rsp.status_code) + " " + rsp.text
        groups = json.loads(rsp.text)
        for group in groups:
            if groupName in group["display"]:
                groupIds.append(group["oid"])
    else:
        return False, "No matching group type"

    return True, groupIds

def getAnalysisPrioritiesList(eda,httpsession,apiKey):
    httpsession.headers.update({'Authorization': 'ExtraHop apikey='+apiKey})

    rsp = httpsession.get('https://'+eda+ANALYSIS_PATH, verify=False)

    if rsp.status_code != 200:
        return False, "status code: "+str(rsp.status_code) + " " + rsp.text

    analysisList = json.loads(rsp.text)

    if len(analysisList) == 0:
        module.exit_json(changed=False)
    else:
        return True, analysisList

def modifyAnalysisPrioritiesList(eda,httpsession,apiKey,priorityList,deviceGroupIDs,action,level,state,types):
    httpsession.headers.update({'Authorization': 'ExtraHop apikey='+apiKey})

    autofill_advanced = priorityList["autofill_advanced"]
    autofill_standard = priorityList["autofill_standard"]
    advanced_rules = priorityList["advanced_rules"] or []
    standard_rules = priorityList["standard_rules"] or []

    if types == "device":
        types = "device_group"
    elif types == "activity":
        types = "activity_group"

    if state == "assigned":
        for deviceGroupID in deviceGroupIDs:
            if level == "advanced":
                if len(advanced_rules) == 0:
                    advanced_rules.append({
                    "type": types,
                    "object_id": deviceGroupID,
                    "description": "added via API"
                    })
                else:
                    for entry in advanced_rules:
                        if deviceGroupID == entry["object_id"]:
                            return False, "DeviceGroup already exists in the list"
                    advanced_rules.append({
                    "type": types,
                    "object_id": deviceGroupID,
                    "description": "added via API"
                    })
            if level == "standard":
                if len(standard_rules) == 0:
                    standard_rules.append({
                    "type": types,
                    "object_id": deviceGroupID,
                    "description": "added via API"
                    })
                else:
                    for entry in standard_rules:
                        if deviceGroupID == entry["object_id"]:
                            return False, "DeviceGroup already exists in the list"
                    standard_rules.append({
                    "type": types,
                    "object_id": deviceGroupID,
                    "description": "added via API"
                            })
    elif state == "unassigned":
        status = False
        for deviceGroupID in deviceGroupIDs:
            if level == "advanced":
                for entry in advanced_rules:
                    if deviceGroupID == entry["object_id"]:
                        advanced_rules.remove(entry)
                        status = True
            if level == "standard":
                for entry in standard_rules:
                    if deviceGroupID == entry["object_id"]:
                        standard_rules.remove(entry)
                        status = True

        if status != True:
            return False, "Unable to remove entry from Analysis Priorities List"
    postBody = {
        "autofill_advanced":autofill_advanced,
        "autofill_standard":autofill_standard,
        "advanced_rules":advanced_rules,
        "standard_rules":standard_rules
    }
    rsp = httpsession.put('https://'+eda+ANALYSIS_PATH, json=postBody, verify=False)

    if rsp.status_code != 204:
        return False, "status code: "+str(rsp.status_code)+" "+rsp.text
    else:
        return True, None

def main():
    module = AnsibleModule(
        argument_spec = dict(
            eda = dict(required=True, type='str'),
            apiKey = dict(required=True, type='str', no_log=True),
            level = dict(required=True, type='str', choices=['advanced','standard']),
            state = dict(required=True, type='str', choices=['assigned','unassigned']),
            types = dict(required=True, type='str', choices=['device','activity']),
            isMemberOf = dict(required=True, type='list')
        ),
    supports_check_mode = False)

    apikey = module.params['apiKey']
    eda = module.params['eda']
    state = module.params['state']
    level = module.params['level']
    types = module.params['types']
    isMemberOf = module.params['isMemberOf']

    # Supress InsecureRequestWarning errors
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SNIMissingWarning)
    requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
    s = requests.Session()

    for groupName in isMemberOf:
        success,data = getDeviceGroupIdsFromGroupName(eda, apikey, s, groupName, types)
        if (success):
            deviceGroupIDs = data
        else:
            module.fail_json(msg=data)

    success, message = getAnalysisPrioritiesList(eda,s,apikey)

    if not success:
        module.fail_json(msg="Unable to get Analysis Priorities List. " + message)
    else:
        priorityList = message

    action = state[0:len(state)-2]

    success, message = modifyAnalysisPrioritiesList(eda,s,apikey,priorityList,deviceGroupIDs,action,level,state,types)
    if not success:
        module.fail_json(msg="Unable to modify Analysis Priorities List. " + message)

    module.exit_json(changed=True)


if __name__ == '__main__':
    main()
