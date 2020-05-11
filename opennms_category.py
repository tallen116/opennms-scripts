#!/usr/bin/python
# -*- coding: utf-8 -*-


from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''

module: opennms_category
short_description: Create and remove OpenNMS category
description:
  - This module will let you create and remove OpenNMS category
author: "Timothy Allen"
options:
  url:
    description: the url to the opennms rest api
    default: 'http://127.0.0.1/opennms/rest'
    required: True
    type: string
    version_added: 0.1.0
  user:
    description: the basic authentication user
    default: admin
    required: True
    type: string
    version_added: 0.1.0
  password:
    description: the password for the user
    default: admin
    required: True
    type: string
    version_added: 0.1.0
  category:
    description: the surveillance category name
    required: True
    type: string
    version_added: 0.1.0
  state:
    description: add or remove a category
    default: present
    type: string
    version_added: 0.1.0
    choices:
      - present
      - absent
  retry:
    description: retry GET and POST request
    default: 1
    type: integer
    version_added: 0.1.0
  group:
    description: the group assigned to the category
    type: string
    version_added: 0.2.0
  node:
    description: the node assigned to the category
    type: string
    version_added: 0.2.0
  foreign_id:
    description: the foreign id of a requisition assigned to the category
    type: string
    version_added: 0.2.0

seealso:
  - module: uri
    description: Interacts with webservices

'''

EXAMPLES = r'''

'''

RETURN = r'''

'''

import xml.etree.ElementTree as ET

from ansible.plugins.action import ActionBase
from ansible.errors import AnsibleError
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.common.validation import check_type_jsonarg, check_type_int, check_type_str
from ansible.utils.display import Display

display = Display()


class ActionModule(ActionBase):
    """ OpenNMS Category action plugin that uses the rest api to keep
        categories idemptotent. """

    TRANSFER_FILES = False

    DEFAULT_URL = 'http://127.0.0.1/opennms/rest'
    DEFAULT_USER = 'admin'
    DEFAULT_PASSWORD = 'admin'
    DEFAULT_URL_PATH = '/categories'
    DEFAULT_STATE = 'present'
    DEFAULT_RETRY = 1

    def check_category(self, category=None, api_request=None):
        """ This will check and see if the category is in the api request.
            It is assumed that the output is json.  It will output True
            if it exists, False if it does not, and None if the parameters
            are not defined. """
        display.debug('{action}: checking {category} with json: {json_data}'.format(
            action=self._task.action,
            category=category,
            json_data=api_request
        ))
        if category == None or api_request == None:
            return None

        for item in api_request['category']:
            if item['name'] == category:
                return True

        return False

    def check_group(self):
        pass

    def check_node(self):
        pass

    def check_foreign_id(self):
        pass

    def create_xml(self, category=None):
        """ Craft the XML to POST to the OpenNMS api.
            
            Example:
            <category id="3" name="Servers"> """

        root = ET.Element('category')
        root.set("name", category)
        
        display.debug('{action}: The XML generated for the post is: {xml_data}'.format(
            action=self._task.action,
            xml_data=ET.tostring(root)
        ))
        return ET.tostring(root)

    def get_uri(self, url=None, user=None, password=None, task_vars=None, tmp=None):
        # Set default uri_args
        uri_args = dict()
        uri_args['url'] = url + self.DEFAULT_URL_PATH
        uri_args['user'] = user
        uri_args['password'] = password
        uri_args['method'] = "GET"
        # 401 - Bad credentials
        # 500 - General error
        uri_args['status_code'] = [200] # removed 404,500
        uri_args['headers'] = {"Accept" : "application/json"}
        uri_args['return_content'] = True            
        display.debug('{action}: running uri module to get category json with {args}'.format(
            action=self._task.action,
            args=uri_args
        ))
        # run GET with uri module Can get 500 code in error
        return self._execute_module(module_name='uri',
            module_args=uri_args,
            task_vars=task_vars, tmp=tmp)

    def post_uri(self, url=None, user=None, password=None,
        category=None, task_vars=None, tmp=None):
        # Set default uri_args
        uri_args = dict()
        uri_args['url'] = url + self.DEFAULT_URL_PATH
        uri_args['user'] = user
        uri_args['password'] = password
        uri_args['method'] = "POST"
        uri_args['status_code'] = [201] # removed 202, 404, 500
        uri_args['headers'] = {"Content-Type" : "application/xml"}
        uri_args['return_content'] = True  
        post_xml = self.create_xml(category=category)
        uri_args['body'] = post_xml
        display.debug('{action}: running the uri module to POST the category with {args}'.format(
            action=self._task.action,
            args=uri_args
        ))
        # run POST request using uri module
        return self._execute_module(module_name='uri',
            module_args=uri_args,
            task_vars=task_vars, tmp=tmp)


    def run(self, tmp=None, task_vars=None):
        ''' handler for template operations '''

        if task_vars == None:
            task_vars = dict()

        super(ActionModule, self).run(tmp, task_vars)
        module_args = self._task.args.copy()

        # assign to local vars
        category = module_args.get('category', None)
        url = module_args.get('url', self.DEFAULT_URL)
        user = module_args.get('user', self.DEFAULT_USER)
        password = module_args.get('password', self.DEFAULT_PASSWORD)
        state = module_args.get('state', self.DEFAULT_STATE)
        retry = module_args.get('retry', self.DEFAULT_RETRY)
        group = module_args.get('group', None)
        node = module_args.get('node', None)
        foreign_id = module_args.get('foreign_id', None)

        try:
            retry = check_type_int(retry)
        except TypeError:
            raise AnsibleError("'retry' is not an integer")


        # logical validation
        if category is None:
            raise AnsibleError("'category' is an undefined required variable")
        elif state != 'present' and state != 'absent':
            raise AnsibleError("'state' is not a valid value")
        elif retry < 0:
            raise AnsibleError("'retry' is a non positive integer")
        #elif group != None and node != None and foreign_id != None:
        #    raise AnsibleError("you have specified more than one type of group, node, or foreign_id")

        display.debug("{action}: The category is: ".format(
            action=self._task.action
        ) + to_text(category))

        display.debug("{action}: The state is: ".format(
            action = self._task.action
        ) + to_text(state))

        _retry = retry
        while _retry >= 0:
            module_return = self.get_uri(url=url, user=user, password=password,
                task_vars=task_vars, tmp=tmp)

            if module_return.get('status', 200) != 200:
                _retry -= 1
            else:
                break

        # Return error if module failed to run
        if module_return.get('failed', False):
            raise AnsibleError('Failed to GET from the REST api, the original error: %s' % to_native(module_return.get('msg')))

        if module_return.get('failed', False):
            raise AnsibleError('The GET request returned a non successful status code {status}: {msg}'.format(
                status=module_return.get('status', None),
                msg=module_return.get('content', None)
            ))

        # setup result var
        result = dict()

        json = module_return.get('json', None)

        if json is None:
            raise AnsibleError('Error retrieving JSON from URI results')

        display.debug('{action}: the JSON returned: {json}'.format(
            action=self._task.action,
            json=json
        ))

        category_exist = self.check_category(category=category, api_request=json)
        #result['category_exist'] = category_exist

        if not category_exist and state == 'present':

            _retry = retry
            while _retry >= 0:
                module_return = self.post_uri(url=url, user=user, password=password,
                    category=category, task_vars=task_vars, tmp=tmp)

                if module_return.get('status', 201) != 201:
                    _retry -= 1
                else:
                    break
            
            if module_return.get('failed', False):
                raise AnsibleError('The POST request returned a non successful status code {status}: {msg}'.format(
                    status=module_return.get('status', None),
                    msg=module_return.get('content', None)
                ))

            display.debug('{action}: Action has made a change on the system'.format(
                action=self._task.action
            ))
            result['changed'] = True

        if group != None:
            pass

        return dict(result)
