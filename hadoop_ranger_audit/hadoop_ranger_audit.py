#!/usr/bin/env python

import argparse
import logging
import getpass
import json
import requests
import os
from shutil import copyfile
from datetime import datetime
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE, ALL_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES

logger = logging.getLogger(__name__)


class Ranger:
    """
    Hadoop Audit Class.
    Matches Ranger Policies to Active Directory users
    """

    def __init__(self, url, user, password):
        self._url = url
        self._user = user
        self._password = password

        logger.debug("Ranger class loaded:")
        logger.debug("Ranger URL: {}".format(self._url))
        logger.debug("Ranger Username: {}".format(self._user))

    def get_service_list(self):
        api_endpoint = 'service/public/v2/api/service'
        logger.info("Fetching list of Ranger services.")
        endpoint = ''.join([self._url,api_endpoint])
        service_list = self.get_json(endpoint=endpoint,parameters=None)

        services = []
        for service in json.loads(service_list.text):
            _id = service['id']
            _name = service['name']
            _enabled = service['isEnabled']
            _type = service['type']

            services.append({'id':_id, 'type':_type, 'name':_name, 'isEnabled':_enabled})

        logger.debug('get_service_list - {}'.format(services))
        return services

    def get_policy_list(self,service):
        api_endpoint = 'service/public/v2/api/service/{}/policy'.format(service['name'])
        endpoint=''.join([self._url, api_endpoint])
        logger.info('Fetching all polices for {}'.format(service['name']))
        police_list = self.get_json(endpoint=endpoint,parameters=None)

        policies = json.loads(police_list.text)
        return policies

    def get_policy_definition(self):
        pass

    def get_groups_from_polies(self,policies, policy_type):
        groups = []
        if policy_type == 'hdfs':
            for policy in policies:
                for policyItem in policy['policyItems']:
                    groups.extend(policyItem['groups'])

        groups = set(groups)
        return groups

    def get_users_from_policies(self,policies, policy_type):
        users = []
        #if policy_type == 'hdfs':
        for policy in policies:
            for policyItem in policy['policyItems']:
                users.extend(policyItem['users'])

        users = set(users)
        return users

    def get_json(self, endpoint,parameters):
        headers={'content-type': 'application/json'}
        logger.debug("Endpoint: {} Parameters: {}".format(endpoint,parameters))
        r = requests.get(endpoint, params=parameters, headers=headers, auth=(self._user, self._password))
        return r


class ActiveDirectory:
    """
    Impliments Active Directory lookups
    """
    def __init__(self, server, user, password):
        self.server = Server(server, get_info=ALL)
        self.conn = Connection(self.server,
                               user=user,
                               password=password,
                               auto_bind=False,
                               authentication=NTLM,
                               return_empty_attributes=True)
        self.conn.open()
        logger.info('Connecting to Active Directory server {}.'.format(self.server))
        self.conn.bind()
        logger.info('Binding to Active Directory.')
        logger.debug('AD connection established, user: {}'.format(self.conn.extend.standard.who_am_i()))

    def _get_members(self, group_name, search_base):
        # Default member_list
        member_list = {'groupname': group_name, 'isADGroup': False, 'members': ''}
        logger.debug('_get_members group_name: {}'.format(group_name))

        g = self.conn.search(
            search_base=search_base,
            search_filter='(&(objectClass=group)(cn={}))'.format(group_name),
            search_scope=SUBTREE,
            paged_size=5,
            attributes=['member'], size_limit=0
        )

        if g:
            if self.conn.entries.__len__() > 0:
                dn = self.conn.entries[0].entry_dn
                members = self.conn.entries[0].member.values
                member_list = {'groupname': group_name, 'isADGroup': True, 'members': members}

        return member_list

    def _get_user_attributes(self, user_search_base):
        # Default user_list
        user_list = {'isADUser': False, 'attributes': ''}

        u = self.conn.search(
            search_base=user_search_base,
            search_filter='(&(objectClass=Person))',
            search_scope=SUBTREE,
            attributes=ALL_ATTRIBUTES,
            paged_size=5,
            size_limit=0
        )

        if u:
            if self.conn.entries.__len__() > 0:
                user_list = {'isADUser': True, 'attributes': self.conn.entries[0]}

        return user_list

    def _get_user_report_attributes(self, user_search_base):
        user = self._get_user_attributes(user_search_base=user_search_base)
        mgr = {}
        if user['isADUser']:
            if self._validate_attribute(user['attributes'], 'manager'):
                manager_dn = self._get_user_attributes(user['attributes']['manager'].value)
                if manager_dn:
                    manager_attributes = self._get_user_attributes(user['attributes']['manager'].value)
                    mgr = {
                        'manager_first_name': manager_attributes['attributes']['givenName'].value,
                        'manager_last_name': manager_attributes['attributes']['sn'].value,
                        'manager_title': manager_attributes['attributes']['title'].value,
                        'manager_mail': str(manager_attributes['attributes']['mail'].value).lower()
                }
            else:
                logger.warning('Unable to retrieve manager attribute for {}.'.format(user['attributes']['sAMAccountName'].value))

            _sAMAccountName = ''
            _first_name = ''
            _last_name = ''
            _title = ''
            _mail = ''

            if self._validate_attribute(user['attributes'], 'sAMAccountName'):
                _sAMAccountName = user['attributes']['sAMAccountName'].value
            if self._validate_attribute(user['attributes'], 'givenName'):
                _first_name = user['attributes']['givenName'].value
            if self._validate_attribute(user['attributes'], 'sn'):
                _last_name=user['attributes']['sn'].value
            if self._validate_attribute(user['attributes'], 'title'):
                _title = user['attributes']['title'].value
            if self._validate_attribute(user['attributes'], 'mail'):
                _mail = str(user['attributes']['mail'].value).lower()

            user_object = {
                    'sAMAccountName': _sAMAccountName,
                    'first_name': _first_name,
                    'last_name': _last_name,
                    'title': _title,
                    'mail': _mail,
                    'manager': [mgr]
                }

        return user_object

    def _validate_attribute(self, object, attribute):
        try:
            value = object[attribute]
            if value:
                return True
            else:
                return False
        except Exception as ex:
            logger.warning('Could not find attribute {} for {}'.format(attribute,object['cn']))
            return False

    def get_ad_group_drilldown(self, group_list, search_base):

        report_list = []
        for group in group_list:
            logger.debug('Group: {}'.format(group))
            user_report = []
            logger.debug(type(user_report))
            group_members = self._get_members(group, search_base)
            if group_members['members'].__len__() > 0:
                for member in group_members['members']:
                    logger.debug('Member: {}'.format(member))
                    r = self._get_user_report_attributes(user_search_base=member)
                    logger.debug('Report: {}'.format(r))
                    user_report.append(r)

            report_list.append({'group': group, 'isADGroup': group_members['isADGroup'], 'member_detail': user_report})

        return report_list

class Report:
    """
    Builds the audit report
    """
    def __init__(self):
        self.script = os.path.dirname(os.path.realpath(__file__))
        self.template = self.script + '/report_template.html'
        logger.info('Script path: {}'.format(self.script))
        self.check_template_file(self.template)

    def check_template_file(self, path):
        try:
            with open(path,'r') as f:
                logger.info("Template file is avilable at {}.".format(path))
        except IOError as x:
            logger.error("Template file not found at {}.".format(path))
            exit(-1)

    def check_write_access(self, output_file):
        try:
            with open(output_file,'w') as f:
                os.remove(output_file)
                logger.info("File: {} is writeable.".format(output_file))
        except IOError as x:
            logger.error("File: {} is not writeable. Error: {}".format(output_file,x.strerror))
            exit(-1)

    def write_report(self, output, data_named_user, data_group_map, data_policies, data_report_properties):
        with open(self.template) as f:
            filedata = f.read()\
                .replace("data_named_user_replace",data_named_user)\
                .replace("data_group_map_replace",data_group_map)\
                .replace("data_policies_replace",data_policies)\
                .replace("data_report_properties_replace",data_report_properties)



        with open(output, 'w') as file:
            file.write(filedata)


def main(args):
    """
    Main method executed when run as a script

    :param args: Instance of argparse
    :return: void
    """

    # region Logging
    # Setup console logging
    stream = logging.StreamHandler()

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)
    #endregion

    #region Test Report Output
    r = Report()
    r.check_write_access(args.output_file)

    #endregion

    # region Ranger_Policy
    # Get Ranger Policy List
    if not args.ranger_url:
        ranger_url = input("Ranger API URL: ")
    else:
        ranger_url = args.ranger_url

    if not args.ranger_user:
        ranger_user = input("Ranger Username: ")
    else:
        ranger_user = args.ranger_user

    if not args.ranger_password:
        ranger_pass = getpass.getpass("Ranger Password: ")
    else:
        ranger_pass = args.ranger_password

    ranger = Ranger(ranger_url, ranger_user, ranger_pass)
    full_service_list = ranger.get_service_list()
    full_group_list = []
    full_policy_list = []
    full_user_list = []

    logger.debug("Services: {}".format(full_service_list))

    # Get all policies
    for service in full_service_list:
        logger.debug("Service: {}".format(service['name']))
        policy_list = ranger.get_policy_list(service=service)
        full_policy_list.append(policy_list)

    logger.debug("Policies: {}".format(json.dumps(full_policy_list)))

    # Get all users and groups
    for service in full_service_list:
        for service_policy in full_policy_list:
            for policy in service_policy:
                logger.debug('Get All Groups - Policy: {} Service: {}'.format(policy['service'], service['name']))
                if policy['service'] == service['name']:
                    group_list = ranger.get_groups_from_polies(policies=service_policy, policy_type=service['type'])
                    full_group_list.extend(group_list)
                    logger.debug("Groups in {} policy: {}".format(service['name'], group_list))

                    user_list = ranger.get_users_from_policies(policies=service_policy, policy_type=service['type'])
                    full_user_list.extend(user_list)
                    logger.debug("Users in {} policy: {}".format(service['name'], user_list))

    full_group_list = set(full_group_list)  # remove duplicates
    full_user_list = set(full_user_list) # remove duplicates
    logger.debug(full_user_list)
    # endregion

    # region Active Directory Lookup
    ad = ActiveDirectory(server=args.ad_controller, user=args.ad_user, password=args.ad_password)
    report_list = ad.get_ad_group_drilldown(full_group_list, args.ad_search_base)
    logger.debug('Group Report: {}'.format(json.dumps(report_list)))

    ad_users = []
    report_users = []
    for group in report_list:
        logger.debug("Group loop: ".format(group))
        for user in group['member_detail']:
            user_name = user['sAMAccountName']
            ad_users.append(user_name)

    # Match AD users and Hadoop local policy users
    u = set(full_user_list).intersection(ad_users)
    anti_u = set(full_user_list) - u

    for uzr in u:
        isad = {'user':uzr, 'isADUser': True}
        report_users.append(isad)
    for auzr in anti_u:
        isad = {'user':auzr, 'isADUser': False}
        report_users.append(isad)

    logger.debug(json.dumps(report_users))
    # endregion

    # region Build Report
    report_properties = [{'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),'cluster':args.cluster_name}]
    r.write_report(output=args.output_file,
                   data_named_user=json.dumps(report_users),
                   data_group_map=json.dumps(report_list),
                   data_policies=json.dumps(full_policy_list),
                   data_report_properties=json.dumps(report_properties)
                   )
    # endregion

    logger.info("Report file written to: {}".format(args.output_file))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ranger_url', help='Base URL for ranger API.', required=True)
    parser.add_argument('--ranger_user', help='', required=True)
    parser.add_argument('--ranger_password', help='', required=True)
    parser.add_argument('--ad_controller', help='Hostname for an Active Directory controller.', required=True)
    parser.add_argument('--ad_user',help='', required=True)
    parser.add_argument('--ad_password',help='', required=True)
    parser.add_argument('--output_file', help='Output file name.', required=True)
    parser.add_argument('--cluster_name', help='Cluster name for report output.', required=True)
    parser.add_argument('--ad_search_base', help='LDAP path where searches will begin', required=True)
    parser.add_argument('--debug', help='Enable debug messages.', action='store_true')

    args = parser.parse_args()

    #Execute if run as a script
    main(args)

