#!/usr/bin/python3

# Copyright: (c) 2022, Thomas Ziegler <toydarian1@gmail.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: godaddy_dns

short_description: Manages dns-records in godaddy

# If this is part of a collection, you need to use semantic versioning,
# i.e. the version is of the form "2.5.0" and not "2.4".
version_added: "1.0.0"

description: Allows to do CRUD operations on domains managed by godaddy using the godaddy-api.

options:
  domain:
    description:
      - The domain to change.
    required: true
    type: str
  name:
    description:
      - This name of the record excluding the I(domain). For example, 
        if you want to set a record for 'sub.my-domain.com', I(name) should be 'sub' and I(domain) 'my-domain.com'.
      - If you want to specify a record for 'my-domain.com'. C(name) should be '@' (this is the default).
    default: '@'
    type: str
    aliases: ['record']
  type:
    description:
      - The type of record.
      - 'SRV' is currently not supported, as the API fails silently when adding the record.
    required: true
    type: str
    choices: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']
  value:
    description:
      - The value, or values, to add, update or delete. Can take a single value or a list of values.
      - If I(state) is 'present', all values are added.
      - If I(state) is 'absent', those values are deleted if present.
      - If I(state) is 'update', only one value is accepted. 
        It will be added or replace the first value matching I(regex). 
        If I(regex) is not defined, and the I(value) is not found, it will be appended to the existing record.
      - If I(state) is 'get', this argument is ignored.
      - If I(type) is 'MX', the record needs to consist of the priority and host separated by one space.
      - If I(type) is 'TXT', don't surround the value with additional quotes or split overly-large entries, 
        otherwise the API will get utterly confused. It will take any string and split it automatically, if necessary.
    type: str
  ttl:
    description:
      - The ttl of the record in seconds.
      - At the time of writing, the godaddy-api allows different values for ttl for different values on the same record.
        This doesn't make sense and is also not reflected in the record you get from the DNS-server.
      - To keep things as consistent, as possible, we update the ttl to the default value if we see different values for
        ttl on different values. This happens if I(state) is 'present', 'update' or 'absent' (but not for 'get') 
        even if nothing else changes and will result in the task showing 'changed'. 
        If an inconsistency is detected when I(state) is 'get', the ttl-field of the return value will be C(-1). 
        In diff-mode, the output will also be C(-1) if an inconsistency was detected.
      - If you want to make sure the ttl doesn't get reset to the default unintentionally, you should always add it to 
        your tasks.
      - The ttl has to be >= 600
    type: int
    default: 3600
  regex:
    description:
      - The regex used to determine what to get, update or delete.
      - Python regexes are supported.
      - Ignored when I(state) is 'present'.
  state:
    description:
      - C(absent) - if neither I(value) nor I(regex) are specified, 
        delete all records of the provided I(type) and I(name). 
        Otherwise, delete all values that match either the regex or are in the list of values
      - C(present) - adds the specified records replacing all existing ones of that I(type) I(name) in the process
      - C(update) - will update the first record that matches I(regex) 
        or add the record if no record matches or exists. Can only take one I(value). 
        Will not do anything if the value is already present, even if there is another value matching I(regex).
        Requires I(value) and I(regex).
      - C(get) - returns the existing records of the provided I(type) and I(name). 
        If I(regex) is specified, return all matching values
    required: true
    type: str
    choices: ['absent', 'present', 'update', 'get']
  api_key:
    description:
      - The API-key to use with the godaddy-api, in the format "<key>:<secret>". If not specified, the module will try 
        to use the C(GODADDY_API_KEY) environment-variable.
    type: str
  url_base:
    description:
      - The url of the godaddy-api you want to use. The default points to the production-api. 
        Use 'https://ote-api.godaddy.com' for development.
    type: str
    default: 'https://api.godaddy.com'
                    
# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
extends_documentation_fragment:
    - my_namespace.my_collection.my_doc_fragment_name

author:
    - Thomas Ziegler (@toydarian)
'''

EXAMPLES = r'''
# get all TXT records for sub.my-domain.com
- name: retrieve TXT record
  godaddy_dns:
    domain: my-domain.com
    name: sub
    type: TXT
    state: get
    
# add or replace existing TXT record
- name: update or set TXT record
  godaddy_dns:
    domain: my-domain.com
    name: sub
    type: TXT
    value: "This is a TXT-record"
    state: present

# add or replace the MX record
- name: update or set the MX record
  godaddy_dns:
    domain: my-domain.com
    type: MX
    value:
      - "10 mail.my-domain.com."
      - "20 mail-2.my-domain.com."

# update the google-site-verification token
- name: update the google-site-verification token
  godaddy_dns:
    domain: my-domain.com
    name: sub
    type: TXT
    value: "google-site-verification:1234567890"
    regex: '^"?google-site-verification:.+$'
    state: update

# append a value to an existing TXT record, if it is not present, yet
- name: ensure a value is part of the record
  godaddy_dns:
    domain: my-domain.com
    name: sub
    type: TXT
    value: "I want this value to be present"
    state: update
    
# delete all A-records
- name: delete A-records
    domain: my-domain.com
    name: sub
    type: A
    state: absent
'''

RETURN = r'''
exists:
  description: Whether the specified record exists
  type: bool
  returned: always
  sample: true
records:
  description: Existing records for the specified I(domain), I(name) and I(type)
  type: complex
  returned: when state is 'get'
  contains:
    domain:
      description: The domain
      type: str
      returned: always
      sample: my-domain.com
    name:
      description: The name
      type: str
      returned: always
      sample: test
    type:
      description: The record-type
      type: str
      returned: always
      sample: TXT
    ttl:
      description: The ttl of the record in seconds. This will be -1 in diffs if the existing ttl was inconsistent.
      type: int
      returned: always
      sample: 3600
    values:
      description: A list of values associated with the record
      type: list
      returned: always
      elements: str
      sample:
        - "google-site-verification:1234abcd"
        - "v=spf1 ip4:123.45.67.89 -all"
'''

import re
import os
import copy

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

_domain_api_version = 'v1'


def _format_for_godaddy(records, with_type=False, with_name=False):
    gd_records = []
    for record in records:
        r = {
            "ttl": record["ttl"],
        }
        if with_name:
            r["name"] = record["record"]
        if with_type:
            r["type"] = record["type"]
        if record["type"] == "MX":
            prio, value = record["value"].split(" ")
            r["priority"] = int(prio)
        elif record["type"] == "SRV":
            srv, proto, prio, weight, port, value = record["value"].split(" ")
            r["service"] = srv
            r["protocol"] = proto
            r["priority"] = int(prio)
            r["weight"] = int(weight)
            r["port"] = int(port)
        else:
            value = record["value"]
        r["data"] = value
        gd_records.append(r)
    return gd_records


def get_records(base, api_key, domain, record, record_type):
    headers = {"Authorization": f"sso-key {api_key}",
               "Accept": "application/json",
               }
    url = f"{base}/{_domain_api_version}/domains/{domain}/records/{record_type}/{record}"
    ret = {
        "records": [],
    }
    r = requests.get(url, headers=headers)
    r_obj = r.json()

    if r.status_code == 200:
        ret["success"] = True
        for ex_record in r_obj:
            record = {
                "record": ex_record["name"],
                "type": ex_record["type"],
                "ttl": ex_record["ttl"],
            }
            if ex_record["type"] == "MX":
                record["value"] = f'{ex_record["priority"]} {ex_record["data"]}'
            elif ex_record["type"] == "SRV":
                record["value"] = f'{ex_record["service"]} {ex_record["protocol"]} {ex_record["priority"]} ' \
                                  f'{ex_record["weight"]} {ex_record["port"]} {ex_record["data"]}'
            else:
                record["value"] = ex_record["data"]
            ret["records"].append(record)
    else:
        ret["success"] = False
        ret["reason"] = r_obj["message"]
        ret["code"] = r_obj["code"]
        ret["status"] = r.status_code
    return ret


def replace_records(base, api_key, domain, record, record_type, records):
    headers = {"Authorization": f"sso-key {api_key}",
               "Accept": "application/json",
               }
    url = f"{base}/{_domain_api_version}/domains/{domain}/records/{record_type}/{record}"
    ret = {}
    body = _format_for_godaddy(records)
    r = requests.put(url, headers=headers, json=body)

    if r.status_code == 200:
        ret["success"] = True
    else:
        r_obj = r.json()
        ret["success"] = False
        ret["reason"] = r_obj["message"]
        ret["code"] = r_obj["code"]
        ret["status"] = r.status_code
    return ret


def add_records(base, api_key, domain, records):
    headers = {"Authorization": f"sso-key {api_key}",
               "Accept": "application/json",
               }
    url = f"{base}/{_domain_api_version}/domains/{domain}/records"
    ret = {}
    body = _format_for_godaddy(records, with_type=True, with_name=True)
    r = requests.patch(url, headers=headers, json=body)

    if r.status_code == 200:
        ret["success"] = True
    else:
        r_obj = r.json()
        ret["success"] = False
        ret["reason"] = r_obj["message"]
        ret["code"] = r_obj["code"]
        ret["status"] = r.status_code
    return ret


def delete_records(base, api_key, domain, record, record_type):
    headers = {"Authorization": f"sso-key {api_key}",
               "Accept": "application/json",
               }
    url = f"{base}/{_domain_api_version}/domains/{domain}/records/{record_type}/{record}"
    ret = {}
    r = requests.delete(url, headers=headers)

    if r.status_code == 204:
        ret["success"] = True
    else:
        r_obj = r.json()
        ret["success"] = False
        ret["reason"] = r_obj["message"]
        ret["code"] = r_obj["code"]
        ret["status"] = r.status_code
    return ret


def _is_record_set_changed(old, new):
    if len(new) != len(old):
        return True
    for i in range(0, len(new)):
        # check if record needs to be updated
        fields = ["ttl", "value"]
        for field in fields:
            if old[i][field] != new[i][field]:
                return True
    return False


def _handle_api_error(module, response):
    if response["status"] == 400:
        module.fail_json("The request was malformed (this is a bug in the module)")
    elif response["status"] == 401:
        module.fail_json("The authentication information (API-token) sent to the API is invalid")
    elif response["status"] == 403:
        module.fail_json("The user identified by the API-token is not allowed to access this domain")
    elif response["status"] == 404:
        module.fail_json("The domain has not been found in the user's account")
    elif response["status"] == 409:
        module.fail_json("The given domain is not eligible to have its records changed")
    elif response["status"] == 422:
        module.fail_json("The specified domain is not a valid domain or the record doesn't fulfill the schema")
    elif response["status"] == 429:
        module.fail_json("We are making too many requests to the API in rapid succession")
    elif response["status"] >= 500:
        module.fail_json("The godaddy-api has an issue, please retry later")
    else:
        module.fail_json(f"Request failed: {response['reason']}")


def _format_record_set(record_set, domain):
    if not record_set:
        return {}
    ttl = record_set[0]["ttl"]
    for r in record_set:
        if r["ttl"] != ttl:
            ttl = -1
    return {
        "domain": domain,
        "name": record_set[0]["record"],
        "type": record_set[0]["type"],
        "ttl": ttl,
        "values": [r["value"] for r in record_set],
    }


def main():
    module_args = dict(
        domain=dict(type='str', required=True),
        type=dict(type='str', required=True,
                  choices=['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA']),
        name=dict(type='str', default='@', aliases=["record"]),
        value=dict(type='list', elements='str'),
        ttl=dict(type='int', default=3600),
        state=dict(type='str', default='present', choices=['get', 'update', 'present', 'absent']),
        regex=dict(type='str'),
        url_base=dict(type='str', default='https://api.godaddy.com'),
        api_key=dict(type='str', no_log=True),
        # delay=dict(type='int', default=0),
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
        required_if=(('state', 'present', ['value']),
                     ('state', 'update', ['value']),
                     )
    )

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib('requests'))

    url_base = module.params.get('url_base').strip('/')
    api_key = module.params.get('api_key') or os.environ["GODADDY_API_KEY"] or None
    domain = module.params.get('domain').strip(".")
    name = module.params.get('name')
    record_type = module.params.get('type')
    ttl_in = module.params.get('ttl')
    value_in = module.params.get('value')
    # delay = module.params.get('delay')
    state = module.params.get('state')
    regex = module.params.get('regex')

    if not api_key:
        module.fail_json("You either need to add the 'api_key' parameter or specify the API-key in the "
                         "'GODADDY_API_KEY' environment-variable")

    if state == "update" and len(value_in) > 1:
        module.fail_json(msg="When using 'update', 'value' may only contain a single value")

    if ttl_in < 600:
        module.fail_json(msg="The ttl has to >= 600")

    response = get_records(url_base, api_key, domain, name, record_type)

    if response["success"]:
        existing_record_set = response["records"]
    else:
        _handle_api_error(module, response)
        existing_record_set = []  # not needed, just here, so IDEs don't complain

    if state == "get":
        # if we only want to get existing records, we are done now and report
        exists = True if existing_record_set else False
        if not exists:
            module.exit_json(changed=False, exists=False)
        else:
            if regex:
                requested_record_set = [r for r in existing_record_set if re.match(regex, r["value"])]
            else:
                requested_record_set = existing_record_set
            module.exit_json(changed=False, exists=True, records=_format_record_set(requested_record_set, domain))

    record_set_from_in = []
    if value_in and state != "absent":
        for value in value_in:
            record_set_from_in.append({
                "record": name,
                "type": record_type,
                # the API doesn't like trailing '.'s on records
                "value": value if not record_type == "MX" else value.strip("."),
                "ttl": ttl_in,
            })

    # In the following block we decide what we need to do
    command = ""
    changed = False
    if not existing_record_set:
        if state in ["update", "present"]:
            # not existing, but has to exist -> create
            command = "replace"
            changed = True
            exists = True
            new_record_set = record_set_from_in
        else:
            # not existing, should not exist -> noop
            command = "noop"
            exists = False
            changed = False
            new_record_set = []
    else:
        if state == "absent" and not regex and not value_in:
            # exists, but should not -> delete
            command = "delete"
            changed = True
            exists = False
            new_record_set = []
        elif state == "absent" and (regex or value_in):
            # exists, but some values should not -> remove existing values
            new_record_set = []
            command = "noop"
            changed = False
            exists = True
            # deep-copy so we don't loose info for diff
            for record in copy.deepcopy(existing_record_set):
                # check if ttl matches
                if record['ttl'] != ttl_in:
                    # ttl doesn't match -> change
                    record['ttl'] = ttl_in
                    changed = True
                    command = "replace"
                # add all records that don't need to be deleted to the new set
                if (value_in and record["value"] in value_in) or (regex and re.match(regex, record["value"])):
                    # the value either matches exactly or matches the regex -> don't add it, replace
                    changed = True
                    command = "replace"
                else:
                    # the value doesn't match exactly or the regex
                    new_record_set.append(record)
            if not new_record_set:
                # if we end up deleting all values, we delete the whole record
                command = "delete"
                changed = True
                exists = False
        elif state == "present":
            # exists and should exist -> check if needs update
            # _is_record_set_changed looks for ttl-changes, as well
            if _is_record_set_changed(existing_record_set, record_set_from_in):
                # needs update -> update
                command = "replace"
                changed = True
                new_record_set = record_set_from_in
            else:
                # doesn't need update -> noop
                command = "noop"
                new_record_set = existing_record_set
            exists = True
        elif state == "update":
            # exists and might need to change/add a record -> check if update, add or is up-2-date
            # deep-copy so we don't loose info for diff
            new_record_set = copy.deepcopy(existing_record_set)
            found_exact_match = False
            found_regex_match = False
            found_ttl_mismatch = False
            for record in new_record_set:
                # check if ttl matches
                if record['ttl'] != ttl_in:
                    # ttl doesn't match -> change
                    record['ttl'] = ttl_in
                    found_ttl_mismatch = True
                # check every record in the set if it matches the regex
                if record["value"] == value_in[0]:
                    found_exact_match = True
                elif regex and re.match(regex, record["value"]):
                    found_regex_match = True

            if not found_exact_match and found_regex_match:
                # we found a regex-match but not an exact match -> update the first match
                changed = True
                command = "replace"
                for record in new_record_set:
                    if re.match(regex, record["value"]):
                        # if the value needs updating -> update value and replace
                        record["value"] = value_in[0]
                        break  # we don't look for more matches
            elif not found_exact_match and not found_regex_match:
                # we found no regex- or exact match -> add value without changing existing records
                new_record_set += record_set_from_in
                command = "add"
                changed = True
                # This will be overwritten later, if we found a ttl-mismatch
            else:
                # we found an exact match -> nothing to do
                changed = False
                command = "noop"

            if found_ttl_mismatch:
                # records of the same type and name can have different ttls in the API.
                # This is weird so we update all values so they have the same ttl
                changed = True
                command = "replace"

            exists = True
        else:
            # should never happen
            raise Exception("The execution reached a point in the code, that should never be reached. "
                            "This is an error in the module. Nothing was changed.")

    if command == "":
        # We weren't able to decide what we need to do. Let's hope we never see this exception.
        raise Exception("Unhandled case. This is an error in the module. Nothing was changed.")

    # In the following block we actually do things
    if not module.check_mode and command != "noop":
        if command == "delete":
            response = delete_records(url_base, api_key, domain, name, record_type)
        elif command == "replace":
            response = replace_records(url_base, api_key, domain, name, record_type, new_record_set)
        elif command == "add":
            # if we use add, we only add the record that was specified as input
            response = add_records(url_base, api_key, domain, record_set_from_in)
        else:
            raise Exception("Case not implemented. This is an error in the module. Nothing was changed.")

        if not response["success"]:
            _handle_api_error(module, response)

    module.exit_json(changed=changed,
                     diff=dict(before={"record": _format_record_set(existing_record_set, domain)},
                               after={"record": _format_record_set(new_record_set, domain)},
                               records=_format_record_set(new_record_set, domain)),
                     exists=exists,
                     )


if __name__ == '__main__':
    main()
