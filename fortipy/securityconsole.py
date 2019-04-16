from __future__ import print_function
import logging
import sys

from fortipy.forti import Forti


logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# logging.getLogger('fortipy.forti').setLevel(logging.DEBUG)


class SecurityConsole(Forti):
    def abort(self, adom):
        '''
        Abort and cancel a security console task.
        '''
        return self._exec_logged_in(url="/securityconsole/abort", adom=adom)

    def assign_package(self, package, target, flags=None):
        '''
        Assign or unassign global policy package to ADOM packages.
        '''
        return self._exec_logged_in(
            url="/securityconsole/assign/package",
            data={
                'pkg': package,
                'target': target,
                'flags': flags or ['none']
            }
        )

    def import_dev_objects(self, adom, name, dst_name, **kwargs):
        '''
        Import objects from device to ADOM, or from ADOM to Global.
        '''
        return self._exec_logged_in(
            url="/securityconsole/import/dev/objs",
            data={
                'adom': adom,
                'name': name,
                'dst_name': dst_name,
                **kwargs
            }
        )

    def install_device(self, adom, scope, flags=None, **kwargs):
        '''
        Installs a device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/device",
            data={
                'adom': adom,
                'scope': scope,
                'flags': flags or ['none'],
                **kwargs
            }
        )

    def install_package(self, adom, package, scope, flags=None, **kwargs):
        '''
        Copy and install a policy package to devices.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/package",
            data={
                'adom': adom,
                'pkg': package,
                'scope': scope,
                'flags': flags or ['none'],
                **kwargs
            }
        )

    def generate_install_preview(self, adom, device, flags=None, vdoms=None):
        '''
        Generate install preview for a device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/preview",
            data={
                'adom': adom,
                'device': device,
                'flags': flags or ['none'],
                'vdoms': vdoms or []
            }
        )

    def cancel_package_install(self, adom):
        '''
        Cancel policy install and clear preview cache. Only to be used when a
        preview cache is previously generated by install/package command
        (install_package method).
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/cancel/install",
            data={'adom': adom}
        )

    def clone_package(self, adom, package, scope, dst_name, dst_parent=None):
        '''
        Clone a policy package within the same ADOM.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/clone",
            data={
                'adom': adom,
                'pkg': package,
                'scope': scope,
                'dst_name': dst_name,
                'dst_parent': dst_parent
            }
        )

    def commit_package(self, adom, scope):
        '''
        Install policies to device from preview cache. Only to be used when a
        preview cache is previously generated by install/package command.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/commit",
            data={'adom': adom, 'scope': scope}
        )

    def move_package(self, adom, package, dst_name='', dst_parent=''):
        '''
        Move and/or rename a policy package within the same ADOM.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/move",
            data={
                'adom': adom,
                'package': package,
                'dst_name': dst_name,
                'dst_parent': dst_parent
            }
        )

    def preview_result(self, adom, device):
        '''
        Retrieve the result of previous install/preview command.
        '''
        return self._exec_logged_in(
            url="/securityconsole/preview/result",
            data={'adom': adom, 'device': device}
        )

    def reinstall_package(self, adom, target, flags=None):
        '''
        Re-install a policy package that had been previously installed.
        '''
        return self._exec_logged_in(
            url="/securityconsole/reinstall/package",
            data={
                'adom': adom,
                'target': target,
                'flags': flags or ['none']
            }
        )

    def sign_certificate_template(self, adom, scope, template):
        '''
        Generate and sign certificate on the target device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/sign/certificate/template",
            data={
                'adom': adom,
                'scope': scope,
                'template': template
            }
        )

    def get_task(self, id_):
        return self._get(url='/task/task/{}'.format(id_))

    def get_tasks(self, **kwargs):
        return self._get(url='/task/task', **kwargs)


def test_policy_install(fm):
    resp = fm.get_devices(adom, filter_=['desc', 'like', 'IPROXY%'])
    scope = []
    for device in resp:
        vdom = device['vdom']
        assert len(vdom) == 1
        device_id = {'name': device['name'], 'vdom': vdom[0]['name']}
        scope.append(device_id)
    pprint(scope)
    res = fm.install_device(adom, scope=scope, flags=['preview'], dev_rev_comments='test')
    pprint(res)
    task_id = res['result'][0]['data']['task']
    pprint(fm.get_tasks(filter_=['user', '==', 'techuser']))


if __name__ == '__main__':
    from . import FortiManager

    from pprint import pprint

    adom = sys.argv[1]
    sc = FortiManager(
        host='fm-bdf.crocodial.de',
        username='techuser',
        password='0d3sSa!0',
        verify=False
    )

    devices = sc.get_devices(
        adom=adom,
        filter_=['desc', 'like', 'IPROXY%']
    )

    print('Devices query response:')
    pprint(devices)

    scope = [
        {
            'name': dev['name'],
            'vdom': dev['vdom'][0]['name']
        }
        for dev in devices
    ]

    print('Generated Scope:')
    pprint(scope)

    res = sc.reinstall_package(
        adom,
        flags=['generate_rev'],
        target=scope
    )
    task_id = res['result'][0]['data']['task']
