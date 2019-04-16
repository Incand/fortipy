'''
FortiManager
Author: Philipp Schmitt <philipp.schmitt@post.lu>
Edited by: Armin Schaare <armin-scha@hotmail.de>
URLs: https://fndn.fortinet.net/index.php?/topic/52-an-incomplete-list-of-url-parameters-for-use-with-the-json-api/
'''

from __future__ import absolute_import
from __future__ import print_function
from .forti import Forti, login_required, toggle_lock
from .securityconsole import SecurityConsole
import json
import logging
import sys

from pprint import pprint


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class FortiManager(SecurityConsole):
    '''
    FortiManager class (SOAP/XML API)
    '''

    # GENERATE_API_BINDINGS(url)

    def get_system_status(self):
        # TODO This method may be common to FortiManager and Analyzer
        return self._get('sys/status')

    def get_serial_number(self):
        return self.get_system_status().get('Serial Number', None)

    def get_version(self):
        return self.get_system_status().get('Version', None)

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

    def get_adoms(self, **kwargs):
        return self._get(
            url='dvmdb/adom',
            request_id=42,
            option='object member',
            **kwargs
        )

    def get_load_balancers(self, adom, **kwargs):
        return self._get(
            url='pm/config/adom/{}/obj/firewall/ldb-monitor'.format(adom),
            request_id=545634,
            **kwargs
        )

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

    def get_policy(self, adom, policy_id, policy_package='default', **kwargs):
        return self.get_policies(
            adom,
            policy_package=policy_package,
            policy_id=policy_id,
            **kwargs
        )

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

    def get_policy_packages(self, adom, **kwargs):
        return self._get(
            url='pm/pkg/adom/{}/'.format(adom),
            request_id=900001,
            **kwargs
        )

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

    def rename_device(self, device):
        '''
        Rename a device
        '''
        pass

    def add_vdom(self, vdom):
        '''
        Create a new VDOM
        '''
        pass

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

    def delete_adom_revision(self, adom, revision_id):
        return self._delete(
            url='dvmdb/adom/{}/revision/{}'.format(adom, revision_id),
            data=None
        )

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

    def add_policy(self, adom='root', policy_pkg='default', data=None):
        return self._add(
            url='pm/config/adom/{}/pkg/{}/firewall/policy'.format(
                adom, policy_pkg
            ),
            adom=adom,
            data=data,
            request_id=666
        )

    def edit_policy(self, adom, policy_id):
        pass

    def add_interface(self, adom='root', data=None):
        return self._add(
            url='pm/config/adom/{}/obj/dynamic/interface'.format(adom),
            adom=adom,
            data=data,
            request_id=667,
        )

    def add_firewall_addresses(self, adom='root', data=None):
        return self._add(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            adom=adom,
            data=data,
            request_id=6670
        )

    def set_firewall_addresses(self, adom='root', data=None):
        return self._set(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            adom=adom,
            data=data,
            request_id=6671
        )

    def update_firewall_addrgrp(self, adom='root', addrgrp_name=None, data=None):
        return self._update(
            url='pm/config/adom/{}/obj/firewall/addrgrp/{}'.format(
                adom, addrgrp_name
            ),
            adom=adom,
            data=data,
            request_id=66700
        )

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

    def get_security_profiles(self, adom, **kwargs):
        '''
        Get security profiles
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall'.format(adom),
            request_id=5723,
            **kwargs
        )

    def get_firewall_addresses(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            request_id=5623,
            **kwargs
        )

    def update_firewall_addresses(self, adom, data, **kwargs):
        '''
        Set all firewall addresses defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/address'.format(adom),
            adom=adom,
            data=data,
            request_id=5624,
            **kwargs
        )

    def delete_firewall_addresses(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/firewall/address/{}'
                 .format(adom, url) for url in data],
            adom=adom,
            request_id=5625
        )

    def get_firewall_proxy_addresses(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            request_id=5626,
            **kwargs
        )

    def set_firewall_proxy_addresses(self, adom, data, **kwargs):
        '''
        Set all firewall addresses defined for an ADOM
        '''
        return self._set(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            adom=adom,
            data=data,
            request_id=5627,
            **kwargs
        )

    def update_firewall_proxy_addresses(self, adom, data, **kwargs):
        '''
        Update all firewall addresses defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/proxy-address'.format(adom),
            adom=adom,
            data=data,
            request_id=5628,
            **kwargs
        )

    def delete_firewall_proxy_addresses(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/firewall/proxy-address/{}'
                 .format(adom, url) for url in data],
            adom=adom,
            request_id=5629
        )

    def get_firewall_addresses6(self, adom):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/address6'.format(adom),
            request_id=562
        )

    def get_firewall_address6_groups(self, adom, **kwargs):
        '''
        Get all firewall addresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/addrgrp6'.format(adom),
            request_id=5622,
            **kwargs
        )

    def get_firewall_address_groups(self, adom, **kwargs):
        '''
        Get all firewall address groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/addrgrp'.format(adom),
            request_id=56227,
            **kwargs
        )

    def update_firewall_address_groups(self, adom, data, **kwargs):
        '''
        Update firewall address groups defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/addrgrp'.format(adom),
            adom=adom,
            data=data,
            request_id=56228,
            **kwargs
        )

    def get_firewall_proxy_address_groups(self, adom, **kwargs):
        '''
        Get all firewall proxy address groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/proxy-addrgrp'.format(adom),
            request_id=56229,
            **kwargs
        )

    def update_firewall_proxy_address_groups(self, adom, data, **kwargs):
        '''
        Update firewall proxy address groups defined for an ADOM
        '''
        return self._update(
            url='pm/config/adom/{}/obj/firewall/proxy-addrgrp'.format(adom),
            adom=adom,
            data=data,
            request_id=56230,
            **kwargs
        )

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

    def get_interfaces(self, adom, **kwargs):
        '''
        Get all interfaces defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/dynamic/interface'.format(adom),
            request_id=5682,
            **kwargs
        )

    def get_services(self, adom, **kwargs):
        '''
        Get all (firewall) services defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/service/custom'.format(adom),
            request_id=5617,
            **kwargs
        )

    def get_firewall_service_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/service/group'.format(adom),
            request_id=5616,
            **kwargs
        )

    def get_schedules(self, adom, **kwargs):
        '''
        Get all scheduless defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/schedule/recurring'.format(adom),
            request_id=5620,
            **kwargs
        )

    def get_firewall_schedule_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/schedule/group'.format(adom),
            request_id=56201,
            **kwargs
        )

    def get_firewall_vips(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/vip'.format(adom),
            request_id=5632,
            **kwargs
        )

    def get_firewall_vip_groups(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/vipgrp'.format(adom),
            request_id=5633,
            **kwargs
        )

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

    def get_traffic_shapers(self, adom, **kwargs):
        '''
        Get all traffic shapers for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/firewall/shaper/traffic-shaper'.format(adom),
            request_id=5037,
            **kwargs
        )

    def get_antivirus_profiles(self, adom, **kwargs):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/root/obj/antivirus/profile'.format(adom),
            request_id=8175,
            **kwargs
        )

    def get_webfilters(self, adom, **kwargs):
        '''
        Get all antivirus profiles defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/webfilter/profile'.format(adom),
            request_id=8177,
            **kwargs
        )

    def get_webfilter_categories(self, adom, **kwargs):
        '''
        Get all webfilter categories
        '''
        return self._get(
            url='/pm/config/adom/{}/obj/webfilter/categories'.format(adom),
            request_id=8179,
            **kwargs
        )

    def get_webfilter_ftgd_local_cats(self, adom, **kwargs):
        '''
        Get all webfilter ftgd local categories
        '''
        return self._get(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-cat'.format(adom),
            request_id=8181,
            **kwargs
        )

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

    def add_webfilter_ftgd_local_ratings(self, adom, data, **kwargs):
        '''
        Add all provided webfilter ftgd local ratings
        '''
        return self._add(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-rating'
                .format(adom),
            adom=adom,
            request_id=8184,
            data=data,
            **kwargs
        )

    def update_webfilter_ftgd_local_ratings(self, adom, data, **kwargs):
        '''
        Update provided webfilter ftgd local ratings
        '''
        return self._update(
            url='/pm/config/adom/{}/obj/webfilter/ftgd-local-rating'
                .format(adom),
            adom=adom,
            request_id=8185,
            data=data,
            **kwargs
        )

    def delete_webfilter_ftgd_local_ratings(self, adom, data):
        '''
        Delete provided webfilter ftgd local ratings
        params:
            data {list[str]} -- A list of rating keys (urls) to delete
        '''
        return self._delete(
            url=['/pm/config/adom/{}/obj/webfilter/ftgd-local-rating/{}'
                 .format(adom, url) for url in data],
            adom=adom,
            request_id=8186
        )

    def get_ips_sensors(self, adom, **kwargs):
        '''
        Get all firewall adresses defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/ips/sensor'.format(adom),
            request_id=9846,
            **kwargs
        )

    def get_application_sensors(self, adom, **kwargs):
        '''
        Get a list of all applications defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/application/list'.format(adom),
            request_id=7850,
            **kwargs
        )

    def get_users(self, adom, **kwargs):
        '''
        Get a list of all local users defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/local'.format(adom),
            request_id=9123,
            **kwargs
        )

    def get_admin_users(self, **kwargs):
        '''
        Get a list of all admin users
        '''
        return self._get(
            url='cli/global/system/admin/user',
            request_id=9125,
            **kwargs
        )

    def json_get_groups(self, adom, **kwargs):
        '''
        Get a list of all user groups defined for an ADOM
        '''
        return self._get(
            url='pm/config/adom/{}/obj/user/group'.format(adom),
            request_id=9124,
            **kwargs
        )

    @login_required
    @toggle_lock
    def install_package(self, adom, package, scope, **kwargs):
        '''
        Copy and install a policy package to devices.
        '''
        return self._exec(
            url="pm/config/adom/{}/securityconsole/install/package".format(adom),
            adom=adom,
            pkg=package,
            scope=scope,
            request_id=5611,
            **kwargs
        )

    @login_required
    @toggle_lock
    def commit_package(self, adom, scope):
        '''
        Install policies to device from preview cache. Only to be used when a
        preview cache is previously generated by install/package command.
        '''
        return self._exec(
            url="pm/config/adom/{}/securityconsole/package/commit".format(adom),
            adom=adom,
            scope=scope,
            request_id=5612
        )

    @login_required
    def get_policy_package(self, adom, name, **kwargs):
        return self._get(url="pm/pkg/adom/{}/{}".format(adom, name), **kwargs)


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

    resp = fm.get_devices(adom, filter_=['desc', 'like', 'IPROXY%'])
    pprint([dev['desc'] for dev in resp])
