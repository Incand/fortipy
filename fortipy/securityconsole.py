from __future__ import print_function
from pprint import pprint
import logging
from functools import wraps
import sys

from fortipy.forti import Forti


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecurityConsole(Forti):
    def error_handler(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            res = func(*args, **kwargs)
            pprint(res)
            return res
        return wrapper

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
            pkg=package,
            target=target,
            flags=flags
        )

    def import_dev_objects(self, adom, name, dst_name, **kwargs):
        '''
        Import objects from device to ADOM, or from ADOM to Global.
        '''
        return self._exec_logged_in(
            url="/securityconsole/import/dev/objs",
            adom=adom,
            name=name,
            dst_name=dst_name,
            **kwargs
        )

    def install_device(self, adom, scope, flags=None, **kwargs):
        '''
        Installs a device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/device",
            adom=adom,
            scope=scope,
            flags=flags,
            **kwargs
        )

    def install_package(self, adom, package, scope, flags=None, **kwargs):
        '''
        Copy and install a policy package to devices.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/package",
            adom=adom,
            pkg=package,
            scope=scope,
            flags=flags,
            **kwargs
        )

    def generate_install_preview(self, adom, device, flags=None, vdoms=None):
        '''
        Generate install preview for a device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/install/preview",
            adom=adom,
            device=device,
            flags=flags,
            vdoms=vdoms
        )

    def cancel_package_install(self, adom):
        '''
        Cancel policy install and clear preview cache. Only to be used when a
        preview cache is previously generated by install/package command
        (install_package method).
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/cancel/install", adom=adom
        )

    def clone_package(self, adom, package, scope, dst_name, dst_parent=None):
        '''
        Clone a policy package within the same ADOM.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/clone",
            adom=adom,
            pkg=package,
            scope=scope,
            dst_name=dst_name,
            dst_parent=dst_parent
        )

    def commit_package(self, adom, scope):
        '''
        Install policies to device from preview cache. Only to be used when a
        preview cache is previously generated by install/package command.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/commit",
            adom=adom,
            scope=scope
        )

    def move_package(self, adom, package, dst_name, dst_parent=None):
        '''
        Move and/or rename a policy package within the same ADOM.
        '''
        return self._exec_logged_in(
            url="/securityconsole/package/move",
            adom=adom,
            package=package,
            dst_name=dst_name,
            dst_parent=dst_parent
        )

    def preview_result(self, adom, device):
        '''
        Retrieve the result of previous install/preview command.
        '''
        return self._exec_logged_in(
            url="/securityconsole/preview/result",
            adom=adom,
            device=device
        )

    def reinstall_package(self, adom, target, flags=None):
        '''
        Re-install a policy package that had been previously installed.
        '''
        return self._exec_logged_in(
            url="/securityconsole/reinstall/package",
            adom=adom,
            target=target,
            flags=flags
        )

    def sign_certificate_template(self, adom, scope, template):
        '''
        Generate and sign certificate on the target device.
        '''
        return self._exec_logged_in(
            url="/securityconsole/sign/certificate/template",
            adom=adom,
            scope=scope,
            template=template
        )


if __name__ == '__main__':
    adom = sys.argv[1]
    sc = SecurityConsole(
        host='fm-bdf.crocodial.de',
        username='techuser',
        password='0d3sSa!0',
        verify=False
    )

    sc.abort(adom=adom)
