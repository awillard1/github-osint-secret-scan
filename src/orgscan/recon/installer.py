"""Explicit, atomic user-local installation from registry-owned Go module paths."""
from contextlib import contextmanager
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from orgscan import processes
from orgscan.recon.registry import controlled_environment, get_registry
from orgscan.security_context import AuthorizationError, LOCAL_CONTEXT, current_auth


def require_tool_admin():
    auth = current_auth.get() or LOCAL_CONTEXT
    # Binaries affect every tenant sharing a worker. Tenant administrators cannot
    # replace executables for other tenants.
    if not auth.allows_role('admin') or '*' not in auth.tenants:
        raise AuthorizationError('Recon tool installation requires a platform administrator')


@contextmanager
def installation_lock(root):
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (root / '.install.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Another tool installation is running') from None
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


class ToolInstaller:
    def __init__(self, settings):
        self.settings = settings
        self.registry = get_registry()

    def install(self, tool_id, *, version='latest'):
        require_tool_admin()
        tool = self.registry.get(tool_id)
        if not tool.go_package:
            raise ValueError('This tool requires manual installation or is built in')
        if version != 'latest' and not re.fullmatch(r'v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?',version):
            raise ValueError('Select latest or an explicit semantic version')
        go = shutil.which(self.settings.recon_go_binary)
        if not go:
            raise ValueError('Configure a Go installation with ORGSCAN_RECON_GO_BINARY first')
        go=str(Path(go).resolve())
        root = self.registry.bin_dir(self.settings).parent
        with installation_lock(root):
            result = {'tool_id':tool_id,'status':'installing','started_at':datetime.now(UTC).isoformat()}
            self._record(root,result)
            try:
                with tempfile.TemporaryDirectory(prefix='install-',dir=root) as staging:
                    stage = Path(staging)
                    target = stage / 'bin'
                    target.mkdir()
                    environment = {**controlled_environment(stage), 'GOBIN':str(target),
                        'GOPATH':str(stage/'go'),'GOCACHE':str(stage/'cache'),'GOTOOLCHAIN':'local',
                        'GOPROXY':'https://proxy.golang.org','GOSUMDB':'sum.golang.org','GOWORK':'off',
                        'GOENV':'off','GOTOOLCHAIN_INTERNAL_SWITCH_VERSION':'','CGO_ENABLED':'1' if tool_id in ('katana','naabu') else '0'}
                    output = processes.run([go,'install',tool.go_package+'@'+version],cwd=stage,env=environment,
                        timeout=self.settings.recon_install_timeout_seconds,max_output_bytes=self.settings.recon_max_output_bytes)
                    if output.returncode:
                        raise ValueError('Go installation failed; check Go version and upstream prerequisites')
                    executable = target / tool.executables[0]
                    if executable.is_symlink() or not executable.is_file() or not os.access(executable,os.X_OK):
                        raise ValueError('Installer did not produce an executable')
                    state = self.registry.readiness(tool_id,self.settings,binary=str(executable))
                    if not state['version']:
                        raise ValueError('Installed executable identity/version verification failed')
                    destination = self.registry.bin_dir(self.settings)
                    destination.mkdir(mode=0o700,exist_ok=True)
                    os.replace(executable,destination/tool.executables[0])
                    result.update(status='completed',version=state['version'])
            except (ValueError,OSError,processes.TimeoutExpired,processes.OutputLimitExceeded):
                result.update(status='failed',error='Installation failed; existing managed binary was preserved')
                self._record(root,result)
                raise ValueError(result['error']) from None
            result['finished_at']=datetime.now(UTC).isoformat()
            self._record(root,result)
            return result

    @staticmethod
    def _record(root,result):
        # Only application labels, timestamps and parsed versions are persisted.
        path=root/'installation.json'
        temp=root/'installation.tmp'
        temp.write_text(json.dumps(result),encoding='utf-8')
        os.replace(temp,path)

    def status(self):
        path=self.registry.bin_dir(self.settings).parent/'installation.json'
        if not path.is_file() or path.stat().st_size>4096:
            return None
        try:
            from orgscan.redaction import redact
            return redact(json.loads(path.read_text()))
        except (ValueError,OSError):
            return None
