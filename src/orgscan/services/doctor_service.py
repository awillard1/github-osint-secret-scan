"""Non-mutating readiness checks. Never serialize settings or exception text."""
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
from urllib.parse import quote

from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from redis import Redis

from orgscan import __version__
from orgscan.auth import load_auth_contexts
from orgscan.db import _alembic_config
from orgscan.providers import available_domain_provider_names
from orgscan.services.scanner_service import scanner_inventory


def _database_checks(settings):
    url = make_url(settings.database_url)
    if url.get_backend_name() == 'sqlite':
        if not url.database or url.database == ':memory:' or not Path(url.database).is_file():
            raise ValueError('Persistent database is missing')
        uri = 'file:' + quote(str(Path(url.database).resolve()), safe='/') + '?mode=ro'
        engine = create_engine('sqlite://', creator=lambda: sqlite3.connect(uri,uri=True,timeout=3))
    elif url.get_backend_name() == 'postgresql':
        engine = create_engine(url,connect_args={'connect_timeout':3})
    else:
        raise ValueError('Unsupported doctor database backend')
    try:
        with engine.connect() as connection:
            connection.execute(text('SELECT 1'))
            tables = inspect(connection).get_table_names()
            revisions = tuple(str(row[0]) for row in connection.execute(text('SELECT version_num FROM alembic_version'))) if 'alembic_version' in tables else ()
            has_users = bool(connection.execute(text('SELECT id FROM users LIMIT 1')).first()) if 'users' in tables else False
            ai_counts=dict(connection.execute(text('SELECT enabled, COUNT(*) FROM local_ai_configurations GROUP BY enabled')).all()) if 'local_ai_configurations' in tables else {}
        return revisions, has_users, ai_counts
    finally:
        engine.dispose()


def _directory_status(path):
    if path.exists():
        return 'ok' if path.is_dir() and os.access(path,os.W_OK | os.X_OK) else 'error'
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return 'warning' if parent.is_dir() and os.access(parent,os.W_OK | os.X_OK) else 'error'


def provider_readiness(settings):
    from orgscan.recon.registry import get_registry
    registry = get_registry()
    rows = []
    for name in registry.definitions:
        state = registry.readiness(name, settings)
        tool = registry.get(name)
        rows.append({'name':name,'display_name':tool.display_name,'status':'ok' if state['ready'] else 'warning',
                     'missing':state['missing'],'mode':tool.mode,'version':state['version'],
                     'scope':'Local readiness only; no target requests made'})
    return rows


def doctor(settings, *, require_queue=False):
    checks = []
    def add(name,status,message,**details):
        checks.append({'name':name,'status':status,'message':message,**details})
    add('runtime','ok' if sys.version_info >= (3,12) else 'error','Python 3.12+ required',
        python='.'.join(map(str,sys.version_info[:3])),orgscan=__version__)
    try:
        from orgscan.services.secret_evidence import encryption_key
        if settings.preserve_secrets:
            encryption_key(settings)
        add('secret-preservation', 'ok', 'Secret preservation: '+('enabled' if settings.preserve_secrets else 'disabled')+
            '; encryption key: '+('configured' if settings.secret_encryption_key else 'missing'))
    except ValueError:
        add('secret-preservation', 'error', 'Secret preservation: enabled; encryption key: missing or invalid')
    if not settings.ai_enabled:
        add('local-ai','ok','Local AI: disabled; protected data disabled')
    else:
        from orgscan.ai.ollama import OllamaProvider
        try:
            state=OllamaProvider(settings,settings.ollama_base_url,settings.ollama_model).health()['status']
        except ValueError:
            state='unavailable'
        add('local-ai','ok' if state=='ready' else 'warning',
            'Local AI: '+state+'; endpoint configured; protected data disabled; source code disabled')
    has_users = False
    try:
        revisions, has_users, ai_counts = _database_checks(settings)
        add('local-ai-configurations','ok','Tenant overrides inventoried without remote requests; use Settings to test each configured endpoint',enabled=ai_counts.get(True,0),disabled=ai_counts.get(False,0))
        add('database','ok','Read-only connectivity succeeded')
    except Exception:
        revisions = ()
        add('database','error','Database unavailable or missing; review configuration and run orgscan init-db explicitly')
    try:
        expected = tuple(ScriptDirectory.from_config(_alembic_config(settings.database_url)).get_heads())
        valid = set(revisions) == set(expected)
        # Only valid Alembic-style identifiers may appear in diagnostics.
        safe_revisions = [value if re.fullmatch(r'[A-Za-z0-9_-]{1,64}',value) else '<invalid>' for value in revisions]
        add('migrations','ok' if valid else 'error','Schema is current' if valid else 'Schema upgrade required; back up before orgscan init-db',
            current=safe_revisions,expected=list(expected))
    except Exception:
        add('migrations','error','Migration resources unavailable; reinstall a complete orgscan package')
    for label,path in (('data',settings.data_dir),('mirrors',settings.data_dir/'mirrors'),('reports',settings.data_dir/'reports')):
        status = _directory_status(path)
        add('directory:'+label,status,'Writable' if status == 'ok' else 'Not present; writable parent exists' if status == 'warning' else 'Directory is not writable')
    add('git','ok' if shutil.which('git') else 'error','Git is required for repository acquisition and history')
    if settings.scan_queue_backend not in {'rq','db'}:
        add('queue','error','Queue backend must be rq or db')
    elif settings.scan_queue_backend == 'db':
        add('queue','ok','Database queue configured; Redis check not applicable')
    else:
        connection = None
        try:
            connection = Redis.from_url(settings.redis_url,socket_connect_timeout=3,socket_timeout=3)
            connection.ping()
            add('queue','ok','Redis/RQ connectivity succeeded')
        except Exception:
            add('queue','error' if require_queue else 'warning','Redis unavailable; required for RQ workers, optional for local scans')
        finally:
            if connection is not None:
                connection.close()
    try:
        settings.scan_queue_retry_interval_list()
        add('retry-config','ok','Retry intervals parse successfully')
    except ValueError:
        add('retry-config','error','Queue retry intervals must be comma-separated integers')
    add('github-token','ok' if settings.github_token else 'warning','Configured' if settings.github_token else 'Not configured; code search unavailable',configured=bool(settings.github_token))
    try:
        contexts = load_auth_contexts(settings)
        enabled = settings.api_auth_required or bool(contexts) or has_users
        add('api-auth','ok' if enabled else 'warning','Authentication enabled' if enabled else 'Unconfigured local mode; configure authentication before network exposure')
        if settings.api_auth_required and not contexts and not has_users:
            add('api-bootstrap','warning','Authentication required but no users/tokens found; bootstrap an administrator')
    except ValueError:
        add('api-auth','error','Invalid ORGSCAN_API_TOKENS_JSON; token values omitted')
    add('browser-cookie','ok' if settings.browser_cookie_secure else 'warning','Secure cookies configured' if settings.browser_cookie_secure else 'Secure cookies disabled; enable behind HTTPS')
    try:
        for row in scanner_inventory(settings):
            readiness = row['readiness']
            version = readiness.get('version') or row['metadata'].get('version')
            if version and not re.fullmatch(r'[0-9][A-Za-z0-9.+_-]{0,63}',str(version)):
                version = None
            add('scanner:'+row['name'],'ok' if readiness['ready'] else 'warning',
                'Ready according to registry' if readiness['ready'] else 'Unavailable; run orgscan scanners for configuration guidance',
                version=version or 'unknown',readiness=readiness['status'])
    except Exception:
        add('scanners','error','Scanner registry unavailable')
    add('semgrep-runtime','warning','Semgrep requires explicit local rules; validate the configured rules against the installed version. Telemetry is off unless explicitly enabled')
    from orgscan.recon.registry import get_registry as recon_registry
    for row in recon_registry().inventory(settings):
        add('recon:'+row['tool_id'],'ok' if row['ready'] else 'warning',row['status'],version=row['version'],mode=row['mode'])
    for row in provider_readiness(settings):
        add('provider:'+row['name'],row['status'],row['scope'],missing=row['missing'])
    return {'ok':not any(row['status']=='error' for row in checks), 'checks':checks,
            'warnings':sum(row['status']=='warning' for row in checks),
            'limitations':['Readiness is not live scanner/provider certification','Directory checks do not test disk capacity or perform writes']}
