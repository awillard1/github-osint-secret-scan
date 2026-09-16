"""Opt-in real tools; all DNS answers and HTTP targets are loopback owned by this test."""
import json
import os
from pathlib import Path
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import dns.message
import dns.rcode
import dns.rrset
import pytest
from sqlalchemy import select

from orgscan import models as m
from orgscan.config import Settings
from orgscan.recon.adapters import Adapter, ReconError
from orgscan.recon.pipeline import pipeline_slot, run_pipeline
from orgscan.recon.registry import get_registry
from orgscan.repositories import Storage
from orgscan.services.assessments.discovery_progress import DiscoveryProgress
from orgscan.services.assessments.workbench import AssessmentWorkbench
from tests.assessments.test_foundation import service

pytestmark = pytest.mark.skipif(os.environ.get('ORGSCAN_LIVE_RECON') != '1', reason='Explicit local recon certification only')
ROOT = 'orgscan.test'
TOOLS = Path(__file__).resolve().parents[2] / 'data/tools'
TEMPLATES = Path(__file__).resolve().parents[1] / 'fixtures/recon/nuclei'


@pytest.fixture
def lab(tmp_path):
    requests = []
    queries = []

    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            raw, sock = self.request
            query = dns.message.from_wire(raw)
            answer = dns.message.make_response(query)
            for question in query.question:
                name = str(question.name).rstrip('.')
                queries.append(name)
                if name not in (ROOT, 'alias.' + ROOT):
                    answer.set_rcode(dns.rcode.NXDOMAIN)
                elif question.rdtype == 1:
                    answer.answer.append(dns.rrset.from_text(question.name, 30, 'IN', 'A', '127.0.0.1'))
                elif question.rdtype == 28:
                    answer.answer.append(dns.rrset.from_text(question.name, 30, 'IN', 'AAAA', '::1'))
                elif question.rdtype == 5 and name.startswith('alias.'):
                    answer.answer.append(dns.rrset.from_text(question.name, 30, 'IN', 'CNAME', ROOT + '.'))
            sock.sendto(answer.to_wire(), self.client_address)

    class HTTP(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            requests.append(self.path)
            code = 302 if self.path == '/redirect' else 404 if self.path == '/missing' else 200
            self.send_response(code)
            self.send_header('Content-Type', 'text/html')
            if code == 302: self.send_header('Location', '/health')
            self.end_headers()
            if self.path == '/.well-known/security.txt':
                self.wfile.write(b'Contact: mailto:security@orgscan.test\nExpires: 2030-01-01T00:00:00Z\n')
            else:
                self.wfile.write(('<html><title>ORGSCAN Local Lab</title>ORGSCAN_LOCAL_CERTIFICATION '+self.path+'<a href="/health">Health</a><a href="/redirect">Redirect</a><a href="/missing">Missing</a><a href="/.well-known/security.txt">Security</a><a href="http://out-of-scope.invalid/">External</a></html>').encode())

    dns_server = socketserver.ThreadingUDPServer(('127.0.0.1', 0), DNS)
    http_server = ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
    import ssl
    from datetime import datetime, timedelta, UTC
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, ROOT)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime.now(UTC)-timedelta(minutes=1))
            .not_valid_after(datetime.now(UTC)+timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(ROOT)]), critical=False).sign(key, hashes.SHA256()))
    key_path, cert_path = tmp_path/'lab-key.pem', tmp_path/'lab-cert.pem'
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    tls_server = ThreadingHTTPServer(('127.0.0.1', 0), HTTP)
    tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
    servers = (dns_server, http_server, tls_server)
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for thread in threads: thread.start()
    try:
        yield {'resolver': '127.0.0.1:' + str(dns_server.server_address[1]),
               'port': http_server.server_port, 'requests': requests, 'queries': queries,
               'tls_url': f'https://{ROOT}:{tls_server.server_port}/',
               'url': f'http://{ROOT}:{http_server.server_port}/'}
    finally:
        for server in servers: server.shutdown(); server.server_close()
        for thread in threads: thread.join(timeout=2)


def configure(settings, lab):
    settings.recon_tools_dir = TOOLS
    settings.recon_resolvers = [lab['resolver']]
    settings.recon_http_ports = [lab['port']]
    settings.nuclei_templates_path = str(TEMPLATES)
    settings.recon_tool_timeout_seconds = 45
    return settings


def required(settings, name):
    state = get_registry().readiness(name, settings)
    assert state['ready'], state
    return state


def test_live_dnsx_httpx_contract(tmp_path, lab):
    settings = configure(Settings(_env_file=None, data_dir=tmp_path), lab)
    adapter = Adapter(settings)
    for name in ('dnsx', 'httpx'): required(settings, name)
    records = adapter.run('dnsx', ROOT, [ROOT, 'alias.' + ROOT])
    assert any(r.kind == 'ip_address' and r.value == '127.0.0.1' for r in records)
    assert any(r.kind == 'ip_address' and r.value == '::1' for r in records)
    assert any(r.attributes.get('dns', {}).get('cname') for r in records)
    missing = adapter.run('dnsx', ROOT, ['missing.' + ROOT])
    assert len(missing) == 1 and missing[0].attributes['dns']['rcode'] == 'NXDOMAIN'
    web = adapter.run('httpx', ROOT, [ROOT])
    assert len(web) == 1, web
    assert web[0].attributes['status'] == 200
    assert web[0].attributes['title'] == 'ORGSCAN Local Lab'
    for path, status in (('redirect', 302), ('missing', 404)):
        output = adapter.run('httpx', ROOT, [lab['url'] + path])
        assert output[0].attributes['status'] == status
        if status == 302: assert output[0].attributes['location'] == '/health'
    assert all(name.endswith(ROOT) for name in lab['queries'])
    settings.recon_http_ports = []
    tls = adapter.run('httpx', ROOT, [lab['tls_url']])
    assert tls[0].value == lab['tls_url'] and tls[0].attributes['status'] == 200


def test_live_subfinder_contract(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, subfinder_sources=['github'])
    required(settings, 'subfinder')
    # GitHub source refuses to query without credentials in its isolated HOME/env.
    adapter = Adapter(settings)
    assert adapter.run('subfinder', ROOT, [ROOT]) == []
    assert adapter.parse('subfinder', ROOT, '') == []
    with pytest.raises(ReconError): adapter.parse('subfinder', ROOT, '{malformed')
    with pytest.raises(ReconError, match='timed out'):
        adapter.run('subfinder', ROOT, [ROOT], timeout=0.0001)


def test_live_nuclei_katana_correlation(service, lab):
    settings = configure(service.settings, lab)
    for name in ('dnsx', 'httpx', 'nuclei', 'katana'): required(settings, name)
    assessment = service.create('a', 'Local live certification')
    with service.factory() as session:
        a = session.get(m.Assessment, assessment['id'])
        storage = Storage(session)
        parent = storage.create_domain(ROOT, organization_id=a.organization_id)
        for _ in range(2):
            progress = DiscoveryProgress(storage)
            run_pipeline(storage, a, parent, {'providers': ['dnsx', 'httpx', 'katana', 'nuclei'], 'active_authorized': True}, settings, progress)
            assert all(s['status'] == 'completed' for s in progress.states.values()), progress.states
            session.commit()
        assert len(list(session.scalars(select(m.Domain)))) == 1
        findings = list(session.scalars(select(m.Finding)))
        assert len(findings) == 1
        assert findings[0].severity == 'info'
        assert findings[0].metadata_json['template_id'] == 'orgscan-local-health'
        endpoints = list(session.scalars(select(m.ReconAsset).where(m.ReconAsset.kind == 'endpoint')))
        health = [e for e in endpoints if e.name == lab['url'] + 'health']
        assert len(health) == 1
        assert {'katana', 'nuclei'} <= set(health[0].metadata_json['observations'])
    work = AssessmentWorkbench(settings)
    assert work.recon_results(a.id, tab='domains')['total'] == 1
    assert work.recon_results(a.id, tab='services')['total'] == 1
    assert work.graph(a.id)['edges']


def test_local_concurrency_limit(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, recon_max_concurrent_jobs=2)
    with pipeline_slot(settings), pipeline_slot(settings):
        with pytest.raises(ReconError, match='concurrency'):
            with pipeline_slot(settings): pass
    with pipeline_slot(settings): pass


def test_live_naabu_connect(tmp_path, lab):
    settings = configure(Settings(_env_file=None, data_dir=tmp_path), lab)
    required(settings, 'naabu')
    class Listener(socketserver.BaseRequestHandler):
        def handle(self): pass
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 8080), Listener)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        rows = Adapter(settings).run('naabu', ROOT, [ROOT])
        assert any(row.kind == 'network_service' and row.value == '127.0.0.1:8080/tcp' for row in rows), rows
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_live_browser_workflow(service, lab, tmp_path, caplog, monkeypatch):
    import re
    from fastapi.testclient import TestClient
    from orgscan.api import create_app
    from orgscan.queueing import enqueue_due_scheduled_scans, run_worker
    from orgscan.services.assessments.jobs import AssessmentJobs
    settings = configure(service.settings, lab)
    import base64, os
    from pydantic import SecretStr
    settings.preserve_secrets=True
    settings.secret_encryption_key=SecretStr(base64.urlsafe_b64encode(os.urandom(32)).decode())
    settings.assessment_allow_local_paths = True
    settings.api_tokens_json = json.dumps([{'name':'operator','token':'local-certification-token','role':'admin','tenants':['*']}])
    repository = tmp_path/'inert-repository'
    repository.mkdir()
    (repository/'configuration.py').write_text('password = "LocalCertificationSynthetic739!"\n')
    browser = TestClient(create_app(settings.database_url, settings=settings), base_url='https://testserver')
    challenge = re.search(r'name="csrf_token" value="([^"]+)"', browser.get('/login').text)[1]
    assert browser.post('/login',data={'token':'local-certification-token','csrf_token':challenge},follow_redirects=False).status_code == 303
    csrf = browser.get('/auth/me').json()['csrf_token']
    def post(path, data):
        return browser.post(path, data={**data,'csrf_token':csrf}, follow_redirects=False)
    response = post('/dashboard/assessments/new', {'tenant':'a','name':'Live local browser certification'})
    assert response.status_code == 303
    identity = int(response.headers['location'].split('/')[3])
    root = f'/dashboard/assessments/{identity}'
    from orgscan.services.assessments.github import ConnectionClient
    hosts=['github.com','ghes-a.example','ghes-b.example']
    for index,host in enumerate(hosts):
        assert post('/dashboard/settings/github',{'tenant':'a','name':host,'connection_type':'github' if index==0 else 'ghes',
            'web_base_url':'https://'+host,'api_base_url':'https://api.github.com' if index==0 else 'https://'+host+'/api/v3'}).status_code==303
    touched=set()
    def github(self,path):
        from urllib.parse import urlsplit
        touched.add(self.web_url)
        route=urlsplit(path).path
        if route.endswith('/languages'):return {'Python':100}
        if '/git/trees/' in route:return {'tree':[]}
        if route.endswith(('/contributors','/commits','/forks','/members','/branches')):return []
        if route.startswith('/search/'):return {'items':[],'total_count':0}
        if route.startswith('/repos/'):
            return {'full_name':'org/repo','name':'repo','html_url':self.web_url+'/org/repo','clone_url':self.web_url+'/org/repo.git',
                'owner':{'login':'org','type':'Organization'},'default_branch':'main','visibility':'public','private':False,'homepage':'http://'+ROOT}
        return []
    monkeypatch.setattr(ConnectionClient,'_request_json',github)
    response = post(root+'/targets', {'text':'\n'.join([ROOT,str(repository),*['https://'+host+'/org/repo' for host in hosts]])})
    assert response.status_code == 200
    assert service.targets(identity)['total'] == 5
    assert post(root+'/launch/discovery',{'profile':'comprehensive-passive','providers':['local-metadata']}).status_code==303
    enqueue_due_scheduled_scans(settings,limit=20)
    run_worker(settings,burst=True,max_jobs=20)
    assert touched=={'https://'+host for host in hosts}
    inventory = browser.get('/dashboard/settings/recon-tools')
    assert inventory.status_code == 200 and str(TOOLS/'bin/httpx') in inventory.text
    for _ in range(2):
        options={'profile':'custom','providers':['dnsx','httpx','katana','nuclei'],'active_authorized':'true'}
        review=post(root+'/launch/discovery',options)
        assert review.status_code==200 and 'Start Active Validation' in review.text
        response = post(root+'/launch/discovery', {**options,'action':'confirmed'})
        assert response.status_code == 303, response.text
        enqueue_due_scheduled_scans(settings, limit=20)
        run_worker(settings, burst=True, max_jobs=20)
    progress = AssessmentJobs(settings).progress(identity)
    assert progress['states'] == {'completed':15}, progress
    stages = [stage for item in progress['items'] for name,stage in item['stages'].items() if name == 'nuclei']
    assert len(stages) == 2 and all(stage['output_count'] == 1 for stage in stages)
    work = AssessmentWorkbench(settings)
    assert work.recon_results(identity, tab='domains')['total'] == 1
    for tab in ('overview','domains','hosts','services','web'):
        response = browser.get(root+'/recon-results?tab='+tab)
        assert response.status_code == 200
    assert post(root+'/selection', {'included':'false'}).status_code == 303
    local=[r for r in work.assets(identity)['items'] if r['entity']['provider']=='local'][0]
    assert post(root+'/selection', {'included':'true','selection_mode':'checked','selected_ids':[local['entity_id']]}).status_code == 303
    scan = {'profile':'quick','scanners':['custom-patterns']}
    assert post(root+'/launch/scan', scan).status_code == 200
    assert post(root+'/launch/scan', {**scan,'action':'confirmed'}).status_code == 303
    enqueue_due_scheduled_scans(settings, limit=20)
    run_worker(settings, burst=True, max_jobs=20)
    assert AssessmentJobs(settings).progress(identity)['repository_jobs']['completed'] == 1
    findings = work.findings(identity)['items']
    assert len(findings) >= 2, findings
    for finding in findings:
        response = browser.get(root+f'/findings/{finding["id"]}')
        assert response.status_code == 200 and 'LocalCertificationSynthetic739!' not in response.text
    for finding in findings:
        secrets=browser.get(f'/findings/{finding["id"]}/secrets').json()['secrets']
        if secrets:
            revealed=browser.post(f'/findings/{finding["id"]}/secrets/{secrets[0]["id"]}/reveal',headers={'X-CSRF-Token':csrf})
            assert revealed.status_code==200 and revealed.json()['value']=='LocalCertificationSynthetic739!'
            break
    else:raise AssertionError('Real local scan did not preserve encrypted evidence')
    for format in ('json','html','csv','pdf','sarif'):
        response = browser.get(f'/assessments/{identity}/reports/{format}')
        assert response.status_code == 200 and b'LocalCertificationSynthetic739!' not in response.content
    from orgscan.ai.ollama import OllamaProvider
    from tests.assessments.test_local_ai import ADVICE
    requests=[]
    def generate(self,text):
        assert 'LocalCertificationSynthetic739!' not in text
        requests.append(text);return ADVICE
    monkeypatch.setattr(OllamaProvider,'generate',generate)
    assert post('/dashboard/settings/local-ai',{'tenant':'a','enabled':'true','base_url':'http://localhost:11434','model':'fixture'}).status_code==200
    assert post(root+'/launch/ai',{'purpose':'summary'}).status_code==303
    enqueue_due_scheduled_scans(settings,limit=20);run_worker(settings,burst=True,max_jobs=20)
    assert len(requests)==1
    assert all(name.endswith(ROOT) for name in lab['queries'])
    assert 'LocalCertificationSynthetic739!' not in caplog.text


def test_live_bounded_parallel_tools(tmp_path, lab):
    from concurrent.futures import ThreadPoolExecutor
    settings = configure(Settings(_env_file=None, data_dir=tmp_path, recon_max_concurrent_jobs=2), lab)
    # Isolate lock files from the workstation's managed installation directory.
    settings.httpx_binary = str(TOOLS/'bin/httpx')
    settings.recon_tools_dir = tmp_path/'tools'
    start = threading.Barrier(12)
    guard = threading.Lock()
    active = peak = 0
    def run(_):
        nonlocal active, peak
        start.wait(timeout=5)
        try:
            with pipeline_slot(settings):
                with guard:
                    active += 1
                    peak = max(peak, active)
                try:
                    assert Adapter(settings).run('httpx', ROOT, [ROOT])
                    return 'completed'
                finally:
                    with guard: active -= 1
        except ReconError as exc:
            assert exc.code == 'capacity'
            return 'capacity'
    with ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(run, range(12)))
    assert peak == 2 and active == 0
    assert 'completed' in results and 'capacity' in results
