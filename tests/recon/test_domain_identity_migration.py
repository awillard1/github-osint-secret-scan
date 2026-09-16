"""Upgrade only disposable 0015 databases; preserve private rows byte-for-byte."""
from datetime import UTC, datetime
import pytest
from alembic import command
from sqlalchemy import MetaData, create_engine, inspect, select
from orgscan.db import _alembic_config, current_db_revision


def legacy(tmp_path):
    url='sqlite:///'+str(tmp_path/'legacy.db')
    command.upgrade(_alembic_config(url),'20260915_0015')
    engine=create_engine(url)
    metadata=MetaData();metadata.reflect(engine)
    return url,engine,metadata.tables


def insert(connection,table,**values):
    # Deterministic non-secret legacy data for all mandatory columns.
    from sqlalchemy import Integer,Float,Boolean,DateTime,LargeBinary,JSON
    row={}
    for column in table.columns:
        if column.name in values or column.nullable or column.primary_key:continue
        typ=column.type
        row[column.name]=(datetime.now(UTC) if isinstance(typ,DateTime) else b'opaque-ciphertext' if isinstance(typ,LargeBinary)
            else {} if isinstance(typ,JSON) else False if isinstance(typ,Boolean) else 0 if isinstance(typ,(Integer,Float)) else 'fixture')
    row.update(values)
    return connection.execute(table.insert().values(**row)).inserted_primary_key[0]


@pytest.mark.parametrize('historical_duplicate', [False, True])
def test_upgrade_preserves_all_private_references_and_ciphertext(tmp_path,historical_duplicate):
    url,engine,t=legacy(tmp_path)
    with engine.begin() as c:
        a=insert(c,t['organizations'],name='A',tenant_key='a')
        b=insert(c,t['organizations'],name='B',tenant_key='b')
        if historical_duplicate:
            c.exec_driver_sql('DROP INDEX ix_domains_name')
            c.exec_driver_sql('CREATE INDEX ix_domains_name ON domains (name)')
        da=insert(c,t['domains'],name='example.com' if historical_duplicate else 'EXAMPLE.com.',organization_id=a,discovered_emails=['a@example.com'],discovery_sources=['httpx'])
        db=insert(c,t['domains'],name='example.com',organization_id=b,discovered_emails=['b@example.com'],discovery_sources=['crtsh'])
        du=insert(c,t['domains'],name='legacy.example',organization_id=None)
        fa=insert(c,t['findings'],domain_id=da,organization_id=a,normalized_hash='a'*64,fingerprint='a'*64,lifecycle_state='REMEDIATED')
        fb=insert(c,t['findings'],domain_id=db,organization_id=b,normalized_hash='b'*64,fingerprint='b'*64)
        insert(c,t['domain_exposures'],domain_id=da,normalized_hash='c'*64)
        insert(c,t['identity_correlations'],domain_id=db)
        insert(c,t['relationships'],from_entity_type='domain',from_entity_id=str(da),to_entity_type='finding',to_entity_id=str(fa))
        insert(c,t['finding_history'],finding_id=fa)
        insert(c,t['secret_evidence'],finding_id=fa,tenant_key='a',fingerprint='d'*64)
        aa=insert(c,t['assessments'],organization_id=a,tenant_key='a')
        insert(c,t['assessment_entities'],assessment_id=aa,entity_type='domain',entity_id=da)
        snapshots={name:list(c.execute(select(table)).mappings()) for name,table in t.items() if name not in ('domains','alembic_version')}
        old_domains={r['id']:dict(r) for r in c.execute(select(t['domains'])).mappings()}
    command.upgrade(_alembic_config(url),'head')
    command.upgrade(_alembic_config(url),'head')
    fresh=MetaData();fresh.reflect(engine)
    with engine.connect() as c:
        for name,rows in snapshots.items():assert list(c.execute(select(fresh.tables[name])).mappings())==rows
        rows={r['id']:dict(r) for r in c.execute(select(fresh.tables['domains'])).mappings()}
        for identity,old in old_domains.items():
            assert {k:v for k,v in rows[identity].items() if k not in ('name','identity_id','tenant_key')}=={k:v for k,v in old.items() if k!='name'}
        assert rows[da]['identity_id']==rows[db]['identity_id']
        assert rows[da]['tenant_key']=='a' and rows[db]['tenant_key']=='b'
        assert rows[du]['organization_id'] is None and rows[du]['tenant_key'] is None
        assert c.exec_driver_sql('PRAGMA foreign_key_check').all()==[]
    assert current_db_revision(url)=='20260916_0016'


def test_ambiguous_same_tenant_normalization_fails_before_mutation(tmp_path):
    url,engine,t=legacy(tmp_path)
    with engine.begin() as c:
        a=insert(c,t['organizations'],name='A',tenant_key='a')
        for name in ('example.com','EXAMPLE.COM.'):
            insert(c,t['domains'],name=name,organization_id=a)
        before=list(c.execute(select(t['domains'])).mappings())
    with pytest.raises(RuntimeError,match='duplicate-association'):
        command.upgrade(_alembic_config(url),'head')
    assert current_db_revision(url)=='20260915_0015'
    assert 'domain_identities' not in inspect(engine).get_table_names()
    with engine.connect() as c:assert list(c.execute(select(t['domains'])).mappings())==before


def test_invalid_legacy_identity_stops_without_logging_value(tmp_path):
    url,engine,t=legacy(tmp_path)
    with engine.begin() as c:
        insert(c,t['domains'],name='not a domain / private value')
    with pytest.raises(RuntimeError,match='identity reconciliation') as error:
        command.upgrade(_alembic_config(url),'head')
    assert 'private value' not in str(error.value)
    assert current_db_revision(url)=='20260915_0015'
    assert 'domain_identities' not in inspect(engine).get_table_names()
