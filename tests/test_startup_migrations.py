import pytest
from sqlalchemy import Column, Integer, Table, inspect

from orgscan.api import create_app
from orgscan.config import Settings
from orgscan.db import create_engine_from_url, init_db, prepare_database
from orgscan.queueing import run_worker


@pytest.mark.parametrize('entry', ['api', 'worker', 'worker-rq', 'database'])
def test_production_startup_checks_schema_without_migrating(tmp_path, monkeypatch, entry):
    settings = Settings(database_url=f'sqlite:///{tmp_path / "production.db"}', app_env='production', auto_migrate=True, scan_queue_backend='db')
    monkeypatch.setattr('orgscan.db.run_migrations', lambda *a: pytest.fail('Startup must not migrate'))
    worker_calls = []
    def start():
        if entry == 'api':
            return create_app(settings.database_url, settings=settings)
        if entry in {'worker', 'worker-rq'}:
            if entry == 'worker-rq':
                import fakeredis
                settings.scan_queue_backend = 'rq'
                # Isolate schema startup from Redis scheduler Lua support.
                monkeypatch.setattr('orgscan.queueing.SafeWorker.work', lambda self, **kwargs: worker_calls.append(kwargs) or False)
                return run_worker(settings, burst=True, connection=fakeredis.FakeRedis())
            return run_worker(settings, burst=True)
        return prepare_database(settings)
    with pytest.raises(RuntimeError, match='orgscan migrate-db'):
        start()
    assert worker_calls == []
    monkeypatch.undo()
    init_db(settings.database_url)
    monkeypatch.setattr('orgscan.db.run_migrations', lambda *a: pytest.fail('Current schema must not migrate'))
    start()
    if entry == 'worker-rq':
        assert len(worker_calls) == 1


def test_explicit_development_bootstrap_and_disable(tmp_path):
    settings = Settings(database_url=f'sqlite:///{tmp_path / "dev.db"}', auto_migrate=False)
    with pytest.raises(RuntimeError, match='migrate-db'):
        prepare_database(settings)
    settings.auto_migrate = True
    prepare_database(settings)
    settings.auto_migrate = False
    prepare_database(settings)


def test_released_baseline_does_not_import_future_models(tmp_path, monkeypatch):
    from orgscan.models import Base
    future = Table('future_unreleased_table', Base.metadata, Column('id', Integer, primary_key=True))
    monkeypatch.setattr('orgscan.redaction.redact', lambda *a, **k: pytest.fail('Migration must use frozen redaction'))
    url = f'sqlite:///{tmp_path / "frozen.db"}'
    try:
        init_db(url)
        engine = create_engine_from_url(url)
        assert future.name not in inspect(engine).get_table_names()
        engine.dispose()
    finally:
        Base.metadata.remove(future)
