'''
FortiManager
Author: Philipp Schmitt <philipp.schmitt@post.lu>
Edited by: Armin Schaare <armin-scha@hotmail.de>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import absolute_import
from __future__ import print_function
from .forti import (login_required, Forti)
import json
import logging
import sys

from pprint import pprint


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


# Custom exceptions
class LockException(Exception):
    pass


class CommitException(Exception):
    pass


def toggle_lock(f):
    '''
    Decorator that locks an ADOM before performing the requested
    action, and then unlocks it again
    '''
    def _wrapper(self, *args, **kwargs):
        '''
        Function to be applied on top of all deorated methods
        '''
        adom = kwargs['adom']
        lock = self.lock_adom(adom=adom)
        logger.debug(lock)
        if lock['result'][0]['status']['code'] != 0:
            raise LockException('Unable to lock ADOM')
        res = f(self, *args, **kwargs)
        commit = self.commit(adom=adom)
        logger.debug(commit)
        if commit['result'][0]['status']['code'] != 0:
            raise CommitException('Unable to commit changes')
        unlock = self.unlock_adom(adom=adom)
        logger.debug(unlock)
        return res
    return _wrapper


# class FortiManagerMeta(type):
#     '''
#     Metaclass for generating url binding methods.
#     '''
#     DEFAULT_URL_METHODS = ['get', 'set', 'add', 'delete', 'clone', 'move', 'exec']
# 
#     '''
#     @login_required
#     def get_security_profiles(self, adom, **kwargs):
#         return self._get(
#             url='pm/config/adom/{}/obj/firewall'.format(adom),
#             request_id=5723,
#             **kwargs
#         )
#     '''
# 
#     API_URLS = [
#         'pm/config/adom/{}/obj/firewall'
#     ]
# 
#     def generate_api_binding_method(api_method, url):
#         name = '_'.join([api_method, url.split('/')[-1]]) + 's'
# 
#         def method(self, adom, kwargs):
#             return self._get(
#                 url=url.format(adom),
#                 request_id=5723,
#                 **kwargs
#             )
#         return name, method
# 
#     def generate_api_binding_methods(url):
#         result = {}
#         for api_method in FortiManagerMeta.DEFAULT_URL_METHODS:
#             method_name, method = FortiManagerMeta.generate_api_binding_method(api_method, url)
#             result[method_name] = method
#         return result
# 
#     def __new__(meta, name, bases, dct):
#         for url in FortiManagerMeta.API_URLS:
#             dct.update(FortiManagerMeta.generate_api_binding_methods(url))
#         pprint(dct)
#         return super(FortiManagerMeta, meta).__new__(meta, name, bases, dct)
# 
# 
# class TestMeta(Forti, metaclass=FortiManagerMeta):
#     pass


class FortiManager(Forti):
    '''
    FortiManager class (SOAP/XML API)
    '''

    # GENERATE_API_BINDINGS(url)

    @login_required
    def get_system_status(self):
        # TODO This method may be common to FortiManager and Analyzer
        return self._get('sys/status')

    @login_required
    def get_serial_number(self):
        return self.get_system_status().get('Serial Number', None)

    @login_required
    def get_version(self):
        return self.get_system_status().get('Version', None)

    @login_required
    def get_hostname(self):
        return self.get_system_status().get('Hostname', None)

    @login_required
    def get_adom_vdom_list(self, verbose=False, skip=False):
        '''
        Get a list of all ADOMs and their assigned VDOMs
        '''
        return self._request(
            'get',
            'dvmdb/adom',
            option='object member',
            request_id=42,
            verbose=verbose
        )

    @login_required
    def get_adoms(self, **kwargs):
        return self._get(
            url='dvmdb/adom',
            request_id=42,
            option='object member',
            **kwargs
        )

    @login_required
    def get_load_balancers(self, adom, **kwargs):
        return self._get(
            url='pm/config/adom/{}/obj/firewall/ldb-monitor'.format(adom),
            request_id=545634,
            **kwargs
        )

    @login_required
    @toggle_lock
    def add_policy_package(self, adom, data):
        '''
        Add a new device policy package
        adom: Name of the parent ADOM (ie. the destination)
        TODO
        '''
        data = [
            {
                "name": "test1",
                "type": "pkg"
            },
            {
                "name": "folder1",
                "type": "folder",
                "subobj": [
                    {
                        "name": "pkg01",
                        "type": "pkg"
                    }
                ]
            }
        ]
        return self._set(
            url="pm/pkg/adom/{}".format(adom),
            data=data,
            request_id=5
        )

    @login_required
    def get_policies(self, adom, policy_id=None, policy_package='default', **kwargs):
        '''
        Read a policy
        If policy_id is supplied retrieve only the corresponding policy
        Otherwise get all policies in package
        '''
        url = 'pm/config/adom/{}/pkg/{}/firewall/policy/{}'.format(
            adom,
            policy_package,
            policy_id if policy_id else ''
        )
        return self._get(url=url, request_id=13789, **kwargs)

    @login_required
    def get_policy(self, adom, policy_id, policy_package='default', **kwargs):
        return self.get_policies(
            adom,
            policy_package=policy_package,
            policy_id=policy_id,
            **kwargs
        )

    @login_required
    def get_all_policies(self, adom, **kwargs):
        policies = []
        policy_packages = self.get_policy_package_names(adom)
        if not policy_packages:
            return
        for polpkg in policy_packages:
            pols = self.get_policies(adom=adom, policy_package=polpkg, **kwargs)
            if pols:
                policies += pols
        return policies

    @login_required
    def get_policy_packages(self, adom, **kwargs):
        return self._get(
            url='pm/pkg/adom/{}/'.format(adom),
            request_id=900001,
            **kwargs
        )

    @login_required
    def get_policy_package_names(self, adom, **kwargs):
        policy_packages = self.get_policy_packages(adom, **kwargs)
        if not policy_packages:
            return
        package_names = []
        for pol_pkg in policy_packages:
            children = pol_pkg.get('subobj')
            if children:
                # FIXME This only works with a depth of one!
                for child in children:
                    package_names.append(
                        '{}/{}'.format(pol_pkg.get('name'), child.get('name')))
            else:
                package_names.append(pol_pkg.get('name'))
        return package_names

    @login_required
    def get_global_policies(self, section='header', policy_id=None, policy_package='default', **kwargs):
        '''
        Read the global policy, specifing the header or footer section
        If policy_id is supplied retrieve only the corresponding policy
        Otherwise get all policies in package
        '''
        url = 'pm/config/global/pkg/{}/global/{}/policy/{}'.format(
            policy_package,
            section,
            policy_id if policy_id else ''
        )
        return self._get(url=url, request_id=13789, **kwargs)

    @login_required
    def rename_device(self, device):
        '''
        Rename a device
        '''
        pass

    @login_required
    def add_vdom(self, vdom):
        '''
        Create a new VDOM
        '''
        pass

    @login_required
    def assign_vdom_to_adom(self, adom, vdom):
        '''
        Assign an ADOM to a VDOM
        '''
        pass

    @login_required
    def get_adom_revision_list(self, adom='default',
                               verbose=False, skip=False):
        '''
        Get a list of all revisions for a given ADOM
        '''
        data = json.dumps(
            {
                "method": "get",
                "params": [
                    {
                        "url": "dvmdb/adom/{}/revision".format(adom)
                    }
                ],
                "id": 899,
                "session": self.token,
                "verbose": verbose,
                "skip": skip
            }
        )
        return self._request(data)

    @login_required
    def create_revision(self, adom, name=None, created_by=None,
                        description=None, locked=False):
        '''
        Create a new revision for a given ADOM
        '''
        if created_by is None:
            created_by = self.credentials.userID
        data = {
            "created_by": created_by,
            "desc": description,
            "locked": locked,
            "name": name
        }
        return self._set(
            url="dvmdb/adom/{}/revision".format(adom),
            data=data,
            request_id=12015
        )

    @login_required
    def delete_adom_revision(self, adom, revision_id):
        return self._delete(
            url='dvmdb/adom/{}/revision/{}'.format(adom, revision_id),
            data=None
        )

    @login_required
    def revert_revision(self, adom, revision_id, name=None, created_by=None,
                        locked=False, description=None):
        '''
        Revert ADOM to a previous revision
        '''
        if created_by is None:
            created_by = self.credentials.userID
        data = {
            "created_by": created_by,
            "desc": description,
            "locked": locked,
            "name": name
        }
        return self._clone(
            url='dvmdb/adom/{}/revision/{}'.format(adom, revision_id),
            request_id=8921,
            data=data
        )

    @login_required
    @toggle_lock
    def add_policy(self, adom='root', policy_pkg='default', data=None):
        return self._add(
            url='pm/config/adom/{}/pkg/{}/firewall/policy'.format(
                adom, policy_pkg
            ),
            data=data,
            request_id=666
        )

    @login_required
    @toggle_lock
    def edit_policy(self, adom, policy_id):
        pass

    # Add objects
    @login_required
    @toggle_lock
    def add_interface(self, adom='root', data=None):
        return self._add(
            url='pm/config/adom/{}/obj/dynamic/interface'.format(adom),
            data=data,
            request_id=667,
        )

    @login_required
    @toggle_lock
    def add_firewall_addresses(self, adom='root', data=None):
        return self._add(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            data=data,
            request_id=6670
        )

    @login_required
    @toggle_lock
    def set_firewall_addresses(self, adom='root', data=None):
        return self._set(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            data=data,
            request_id=6671
        )

    # Update existing objects
    @login_required
    @toggle_lock
    def update_firewall_addrgrp(self, adom='root', addrgrp_name=None, data=None):
        return self._update(
            url='pm/config/adom/{}/obj/firewall/addrgrp/{}'.format(
                adom, addrgrp_name
            ),
            data=data,
            request_id=66700
        )

    @login_required
    @toggle_lock
    def delete_policy(self, policy_id, adom='root', policy_pkg='default'):
        '''
        Delete a policy
        '''
        return self._delete(
            url='pm/config/adom/{}/pkg/{}/firewall/policy/{}'.format(
                adom, policy_pkg, policy_id
            ),
            data=None,
            request_id=89561
        )

    @login_required
    @toggle_lock
    def delete_interface(self, interface, adom='root'):
        '''
        Delete an interface
        '''
        return self._delete(
            url='pm/config/adom/{}/obj/dynamic/interface/{}'.format(
                adom, interface
            ),
            data=None
        )

    @login_required
    def get_security_profiles(self, adom, **kwargs):
        '''
        Get security profiles
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall'.format(adom),
            request_id=5723,
            **kwargs
        )

    @login_required
    def get_firewall_addresses(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            request_id=5623,
            **kwargs
        )

    @login_required
    def update_firewall_addresses(self, adom, data, **kwargs):
        '''
        Set all firewall addresses defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            data=data,
            request_id=5624,
            **kwargs
        )

    @login_required
    @toggle_lock
    def delete_firewall_addresses(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/firewall/address/{}'
                 .format(adom, url) for url in data],
            request_id=5625
        )

    @login_required
    def get_firewall_proxy_addresses(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            request_id=5626,
            **kwargs
        )

    @login_required
    @toggle_lock
    def set_firewall_proxy_addresses(self, adom, data, **kwargs):
        '''
        Set all firewall addresses defined for an ADOM
        '''
        return self._set(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            data=data,
            request_id=5627,
            **kwargs
        )

    @login_required
    @toggle_lock
    def update_firewall_proxy_addresses(self, adom, data, **kwargs):
        '''
        Update all firewall addresses defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            data=data,
            request_id=5628,
            **kwargs
        )

    @login_required
    @toggle_lock
    def delete_firewall_proxy_addresses(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/firewall/proxy-address/{}'
                 .format(adom, url) for url in data],
            request_id=5629
        )

    @login_required
    def get_firewall_addresses6(self, adom):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/address6'.format(adom),
            request_id=562
        )

    @login_required
    def get_firewall_address6_groups(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/addrgrp6'.format(adom),
            request_id=5622,
            **kwargs
        )

    @login_required
    def get_firewall_address_groups(self, adom, **kwargs):
        '''
        Get all firewall address groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/addrgrp'.format(adom),
            request_id=56227,
            **kwargs
        )

    @login_required
    def update_firewall_address_groups(self, adom, data, **kwargs):
        '''
        Update firewall address groups defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/addrgrp'.format(adom),
            data=data,
            request_id=56228,
            **kwargs
        )

    @login_required
    def get_firewall_proxy_address_groups(self, adom, **kwargs):
        '''
        Get all firewall proxy address groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/proxy-addrgrp'.format(adom),
            request_id=56229,
            **kwargs
        )

    @login_required
    def update_firewall_proxy_address_groups(self, adom, data, **kwargs):
        '''
        Update firewall proxy address groups defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/proxy-addrgrp'.format(adom),
            data=data,
            request_id=56230,
            **kwargs
        )

    @login_required
    def get_firewall_address_group(self, adom, addrgrp_name, **kwargs):
        '''
        Get all firewall adress groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/addrgrp/{}'.format(
                adom, addrgrp_name
            ),
            request_id=562270,
            **kwargs
        )

    @login_required
    def get_interfaces(self, adom, **kwargs):
        '''
        Get all interfaces defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/dynamic/interface'.format(adom),
            request_id=5682,
            **kwargs
        )

    @login_required
    def get_services(self, adom, **kwargs):
        '''
        Get all (firewall) services defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/service/custom'.format(adom),
            request_id=5617,
            **kwargs
        )

    @login_required
    def get_firewall_service_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/service/group'.format(adom),
            request_id=5616,
            **kwargs
        )

    @login_required
    def get_schedules(self, adom, **kwargs):
        '''
        Get all scheduless defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/schedule/recurring'.format(adom),
            request_id=5620,
            **kwargs
        )

    @login_required
    def get_firewall_schedule_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/schedule/group'.format(adom),
            request_id=56201,
            **kwargs
        )

    @login_required
    def get_firewall_vips(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/vip'.format(adom),
            request_id=5632,
            **kwargs
        )

    @login_required
    def get_firewall_vip_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/vipgrp'.format(adom),
            request_id=5633,
            **kwargs
        )

    @login_required
    def get_devices(self, adom=None, **kwargs):
        '''
        Get all devices defined for an ADOM
        If adom is undefined return all devices
        '''
        return self._get(
            url='dvmdb/adom/{}/device'.format(adom) if adom else 'dvmdb',
            request_id=7465,
            **kwargs
        )

    @login_required
    def get_traffic_shapers(self, adom, **kwargs):
        '''
        Get all traffic shapers for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/shaper/traffic-shaper'.format(adom),
            request_id=5037,
            **kwargs
        )

    # Profiles

    @login_required
    def get_antivirus_profiles(self, adom, **kwargs):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/root/obj/antivirus/profile'.format(adom),
            request_id=8175,
            **kwargs
        )

    @login_required
    def get_webfilters(self, adom, **kwargs):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/webfilter/profile'.format(adom),
            request_id=8177,
            **kwargs
        )

    @login_required
    def get_webfilter_categories(self, adom, **kwargs):
        '''
        Get all webfilter categories
        '''
        return self._get(
            url='/pm/config/adom/{}/obj/webfilter/categories'.format(adom),
            request_id=8179,
            **kwargs
        )

    @login_required
    def get_webfilter_ftgd_local_cats(self, adom, **kwargs):
        '''
        Get all webfilter ftgd local categories
        '''
        return self._get(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-cat'.format(adom),
            request_id=8181,
            **kwargs
        )

    @login_required
    def get_webfilter_ftgd_local_ratings(self, adom, **kwargs):
        '''
        Get all webfilter ftgd local ratings
        '''
        return self._get(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-rating'
                .format(adom),
            request_id=8183,
            **kwargs
        )

    @login_required
    def add_webfilter_ftgd_local_ratings(self, adom, data, **kwargs):
        '''
        Add all provided webfilter ftgd local ratings
        '''
        return self._add(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-rating'
                .format(adom),
            request_id=8184,
            data=data,
            **kwargs
        )

    @login_required
    def update_webfilter_ftgd_local_ratings(self, adom, data, **kwargs):
        '''
        Update provided webfilter ftgd local ratings
        '''
        return self._update(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-rating'
                .format(adom),
            request_id=8185,
            data=data,
            **kwargs
        )

    @login_required
    def delete_webfilter_ftgd_local_ratings(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/webfilter/ftgd-local-rating/{}'
                 .format(adom, url) for url in data],
            request_id=8186
        )

    @login_required
    def get_ips_sensors(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/ips/sensor'.format(adom),
            request_id=9846,
            **kwargs
        )

    @login_required
    def get_application_sensors(self, adom, **kwargs):
        '''
        Get a list of all applications defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/application/list'.format(adom),
            request_id=7850,
            **kwargs
        )

    @login_required
    def get_users(self, adom, **kwargs):
        '''
        Get a list of all local users defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/local'.format(adom),
            request_id=9123,
            **kwargs
        )

    @login_required
    def json_get_groups(self, adom, **kwargs):
        '''
        Get a list of all user groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/group'.format(adom),
            request_id=9124,
            **kwargs
        )

    # Workspace functions (FortiManager 5 Patch Release 3)

    @login_required
    def lock_adom(self, adom):
        '''
        Lock an ADOM
        '''
        return self._exec(url="pm/config/adom/{}/_workspace/lock".format(adom), request_id=5612)

    @login_required
    def unlock_adom(self, adom):
        '''
        Unclock an ADOM
        '''
        return self._exec(url="pm/config/adom/{}/_workspace/unlock".format(adom), request_id=5613)

    @login_required
    def commit(self, adom):
        '''
        Commit changes made to ADOM
        '''
        return self._exec(url="pm/config/adom/{}/_workspace/commit".format(adom), request_id=5614)


if __name__ == '__main__':
    host = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    adom = sys.argv[4]
    fm = FortiManager(
        host=host,
        username=username,
        password=password,
        verify=False
    )

    resp = fm.get_firewall_address_groups(adom)

    old_member = [
        'BDFDEHAMDC100000LB05-10.9.7.2',
        'BDFDEHAMDC500000LB06-10.9.7.3',
        'INT-217.111.75.1-COLT-Router',
        'INT-194.175.243.97-UUNet-Router',
        'INT-221.232.147.92-WUH-ISP',
        'DMZ-BDFCNWUHPC-Net-10.191.254.32',
        'DMZ-BDFDEHAMA2142-192.168.199.132-Cisco-ExpressGW',
        'GRP-FW-Module',
        'DMZ-BDFCNWUH-10.191.254.154-DMZ03-C390-1',
        'DMZ-BDFCNWUH-10.191.254.155-DMZ03-C390-2',
        'DMZ-BDFDEHAM00000000LA02-192.168.198.45-FortiAnalyzer',
        'DMZ-BDFDEHAMDC100000MA02-192.168.198.44-FortiManager',
        'Net-192.168.0.0'
    ]

    resp = fm.update_firewall_addrgrp(
        adom=adom,
        addrgrp_name='GRP-NTP-Clients',
        data={'member': old_member}
    )

    pprint(resp)
