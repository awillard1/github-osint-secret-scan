"""Frozen pre-0016 fixture writes, independent of the current Domain mapper."""
from datetime import UTC, datetime
from types import SimpleNamespace
from orgscan.migration_snapshots.phase17_schema import metadata


def domain(storage, name, organization_id=None):
    now=datetime.now(UTC)
    values=dict(name=name,organization_id=organization_id,ownership_confidence='unverified',verification_status='unverified',
                discovered_emails=[],discovered_subdomains=[],discovery_sources=[],created_at=now,updated_at=now)
    result=storage.session.connection().execute(metadata.tables['domains'].insert().values(**values))
    return SimpleNamespace(id=result.inserted_primary_key[0],**values)


def exposure(storage,domain_id,source,*,source_name,result_summary,normalized_hash):
    now=datetime.now(UTC)
    values=dict(domain_id=domain_id,source=source,source_name=source_name,result_summary=result_summary,
                normalized_hash=normalized_hash,source_class='free',confidence='unverified',severity='info',
                first_seen=now,last_seen=now,created_at=now,updated_at=now)
    result=storage.session.connection().execute(metadata.tables['domain_exposures'].insert().values(**values))
    return SimpleNamespace(id=result.inserted_primary_key[0],**values)
