"""Direct coverage for the artifact application boundary."""
from io import BytesIO
import tarfile
import zipfile

import pytest
from fastapi.testclient import TestClient

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.scanners.external import ScannerExecutionError
from orgscan.security_context import AuthContext, AuthorizationError, current_auth
from orgscan.services import artifact_service as artifacts


@pytest.fixture
def service(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'artifact.db'}", data_dir=tmp_path / "data")
    init_db(settings.database_url)
    return artifacts.ArtifactScanService(create_session_factory(settings.database_url), settings)


def test_successful_scan_and_cleanup(service, monkeypatch, tmp_path):
    monkeypatch.setattr(artifacts, "TemporaryDirectory", lambda **kw: _temporary(tmp_path, **kw))
    result = service.scan_upload(filename="fixture.txt", content=b"inert fixture")
    assert result["artifact_name"] == "fixture.txt" and result["findings"] == 0
    assert result["extracted"] is False
    assert not list(tmp_path.glob("orgscan-artifact-*"))
    with service.session_factory() as session:
        assert Storage(session).get_scan_job(result["scan_job_id"]).target_type == "artifact"


def _temporary(root, **kwargs):
    from tempfile import TemporaryDirectory
    return TemporaryDirectory(dir=root, **kwargs)


def test_invalid_scanner_and_target_context(service):
    with pytest.raises(ValueError):
        service.scan_upload(filename="fixture.txt", content=b"inert", scanner_name="unknown-scanner")
    with pytest.raises(ValueError):
        service.scan_upload(filename="fixture.txt", content=b"inert", profile="domain-only")


def test_scanner_readiness_failure_propagates_safely(service):
    with pytest.raises(ScannerExecutionError, match="not ready") as exc:
        service.scan_upload(filename="fixture.txt", content=b"inert", scanner_name="semgrep")
    assert "inert" not in str(exc.value)


def test_tenant_scope_rejected_before_scan(service, monkeypatch):
    with service.session_factory() as session:
        storage = Storage(session)
        storage.get_or_create_organization("private-org", tenant_key="private")
        session.commit()
    monkeypatch.setattr(artifacts, "execute_plan", lambda *args, **kwargs: pytest.fail("scan executed"))
    marker = current_auth.set(AuthContext("other", "analyst", ("other",), True))
    try:
        with pytest.raises(AuthorizationError):
            service.scan_upload(filename="fixture.txt", content=b"inert", organization="private-org")
    finally:
        current_auth.reset(marker)


def test_mismatched_organization_and_repository_rejected(service):
    with service.session_factory() as session:
        storage = Storage(session)
        first, _ = storage.get_or_create_organization("first", tenant_key="private")
        storage.get_or_create_organization("second", tenant_key="private")
        storage.get_or_create_repository("first/repo", organization_id=first.id)
        session.commit()
    marker = current_auth.set(AuthContext("analyst", "analyst", ("private",), True))
    try:
        with pytest.raises(AuthorizationError, match="scopes do not match"):
            service.scan_upload(filename="fixture.txt", content=b"inert",
                                organization="second", repository="first/repo")
    finally:
        current_auth.reset(marker)


def test_limits_and_archive_rejection(service, tmp_path):
    with pytest.raises(artifacts.ArtifactInputError) as exc:
        service.scan_upload(filename="large.txt", content=b"x" * (artifacts.MAX_ARTIFACT_UPLOAD_BYTES + 1))
    assert exc.value.code == "too_large"
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape", "inert")
    with pytest.raises(artifacts.ArtifactInputError):
        service.scan_upload(filename="bundle.zip", content=archive.getvalue())
    assert not (tmp_path / "escape").exists()


@pytest.mark.parametrize("kind", ["symlink", "fifo"])
def test_tar_special_entries_rejected(service, kind):
    archive = BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as handle:
        entry = tarfile.TarInfo("unsafe")
        entry.type = tarfile.SYMTYPE if kind == "symlink" else tarfile.FIFOTYPE
        if kind == "symlink":
            entry.linkname = "../outside"
        handle.addfile(entry)
    with pytest.raises(artifacts.ArtifactInputError):
        service.scan_upload(filename="bundle.tar", content=archive.getvalue())


def test_zip_symlink_rejected(service):
    archive = BytesIO()
    with zipfile.ZipFile(archive, "w") as handle:
        entry = zipfile.ZipInfo("unsafe")
        entry.create_system = 3
        entry.external_attr = 0o120777 << 16
        handle.writestr(entry, "../outside")
    with pytest.raises(artifacts.ArtifactInputError):
        service.scan_upload(filename="bundle.zip", content=archive.getvalue())


@pytest.mark.parametrize("failure", [RuntimeError("scan failed"), ScannerExecutionError("Scanner timed out")])
def test_scan_failure_cleans_workspace(service, monkeypatch, tmp_path, failure):
    monkeypatch.setattr(artifacts, "TemporaryDirectory", lambda **kw: _temporary(tmp_path, **kw))
    def fail(*args, **kwargs):
        raise failure
    monkeypatch.setattr(artifacts, "execute_plan", fail)
    with pytest.raises(type(failure)):
        service.scan_upload(filename="fixture.txt", content=b"inert")
    assert not list(tmp_path.glob("orgscan-artifact-*"))


def test_archive_error_does_not_disclose_parser_diagnostics(service, monkeypatch):
    marker = "UNTRUSTED_ARCHIVE_CONTENT"
    def fail(*args, **kwargs):
        raise ValueError(marker)
    monkeypatch.setattr(artifacts, "_extract_zip_artifact", fail)
    with pytest.raises(artifacts.ArtifactInputError) as exc:
        service.scan_upload(filename="bundle.zip", content=b"inert")
    assert marker not in str(exc.value) and exc.value.__cause__ is None


def test_api_archive_error_response_omits_parser_diagnostics(service, monkeypatch):
    marker = "UNTRUSTED_ARCHIVE_CONTENT"
    def fail(*args, **kwargs):
        raise ValueError(marker)
    monkeypatch.setattr(artifacts, "_extract_zip_artifact", fail)
    client = TestClient(create_app(service.settings.database_url, settings=service.settings))
    response = client.post("/artifact-scans", files={"artifact": ("bundle.zip", b"inert")})
    assert response.status_code == 400
    assert marker not in response.text
