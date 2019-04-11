import pytest


class TestSecurityConsole:
    @pytest.fixture
    def adom(self):
        return 'BDF_5_6'

    @pytest.fixture(params=[{
        'host': 'fm-bdf.crocodial.de',
        'username': 'techuser',
        'password': '0d3sSa!0',
        'verify': False
    }])
    def security_console(self, request):
        from fortipy.securityconsole import SecurityConsole
        return SecurityConsole(**request.param)

    def test_abort(self, security_console, adom):
        assert security_console.abort(adom)

    def test_assign_package(self, security_console, adom):
        assert security_console.assign_package(package='', target='')

    def test_import_dev_objects(self, security_console, adom):
        assert security_console.import_dev_objects(
            adom, name=None, dst_name=None)

    def test_install_device(self, security_console, adom):
        assert security_console.install_device(adom, scope=None)

    def test_install_package(self, security_console, adom):
        assert security_console.install_package(adom, package=None, scope=None)

    def test_generate_install_preview(self, security_console, adom):
        assert security_console.generate_install_preview(
            adom, device=None)

    def test_cancel_package_install(self, security_console, adom):
        assert security_console.cancel_package_install(adom)

    def test_clone_package(self, security_console, adom):
        assert security_console.clone_package(
            adom, package=None, scope=None, dst_name=None)

    def test_commit_package(self, security_console, adom):
        assert security_console.commit_package(adom, scope=None)

    def test_move_package(self, security_console, adom):
        assert security_console.move_package(
            adom, package=None, dst_name=None, dst_parent=None)

    def test_preview_result(self, security_console, adom):
        assert security_console.preview_result(adom, device=None)

    def test_reinstall_package(self, security_console, adom):
        assert security_console.reinstall_package(adom, target=None)

    def test_sign_certificate_template(self, security_console, adom):
        assert security_console.sign_certificate_template(
            adom, scope=[], template='')
