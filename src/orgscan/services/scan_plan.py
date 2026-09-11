"""Resolved, serializable scan intent shared by interactive and job adapters."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from orgscan.config import Settings
from orgscan.scanners import get_registry


class ScanProfile(BaseModel):
    model_config = ConfigDict(frozen=True)
    scanners: tuple[str, ...] = ()
    discovery_provider: str | None = None
    history_policy: Literal['all', 'current-ref'] = 'all'


PROFILES = {
    'quick': ScanProfile(scanners=('custom-patterns',)),
    'standard': ScanProfile(scanners=('custom-patterns', 'repo-governance')),
    'comprehensive': ScanProfile(scanners=('custom-patterns', 'repo-governance', 'gitleaks', 'detect-secrets', 'semgrep', 'trufflehog', 'yara', 'ripgrep-heuristics')),
    'history': ScanProfile(scanners=('git-history-patterns',)),
    'secrets-only': ScanProfile(scanners=('custom-patterns', 'gitleaks', 'detect-secrets', 'trufflehog')),
    'osint-only': ScanProfile(discovery_provider='github-search'),
    'domain-only': ScanProfile(discovery_provider='local-metadata'),
    'governance-only': ScanProfile(scanners=('repo-governance',)),
}


class ScanPlan(BaseModel):
    model_config = ConfigDict(frozen=True, extra='forbid')
    version: Literal[1] = 1
    target: str = Field(min_length=1)
    target_type: Literal['path', 'artifact', 'mirror', 'domain'] = 'path'
    profile: str | None = None
    scanners: tuple[str, ...] = ()
    refs: tuple[str, ...] = ()
    branch_policy: Literal['default-only', 'selected', 'all'] = 'default-only'
    history_policy: Literal['all', 'current-ref'] = 'all'
    mode: Literal['full', 'incremental', 'history'] = 'full'
    discovery_provider: str | None = None
    timeout_seconds: float = Field(default=300, gt=0, allow_inf_nan=False)
    organization_id: int | None = None
    repository_id: int | None = None
    tenant_key: str | None = None
    scope: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode='after')
    def compatible(self):
        if self.profile is not None and self.profile not in PROFILES:
            raise ValueError('Unknown scan profile')
        if len(set(self.scanners)) != len(self.scanners) or len(set(self.refs)) != len(self.refs):
            raise ValueError('Duplicate scanners or refs in resolved plan')
        if self.target_type == 'domain':
            if self.scanners or not self.discovery_provider or self.refs or self.mode != 'full':
                raise ValueError('Domain plans require discovery only, without repository scope')
        elif not self.scanners or self.discovery_provider:
            raise ValueError('File/repository plans require scanners and cannot run domain discovery')
        if self.target_type != 'mirror' and (self.refs or self.branch_policy != 'default-only' or self.mode == 'incremental'):
            raise ValueError('Branch selection and incremental mode require a mirror target')
        if self.branch_policy == 'selected' and not self.refs:
            raise ValueError('Selected branch policy requires refs')
        if self.refs and self.branch_policy != 'selected':
            raise ValueError('Explicit refs require selected branch policy')
        if any(not ref.strip() or ref.startswith('-') for ref in self.refs):
            raise ValueError('Invalid ref selection')
        return self

    def serialized(self) -> dict:
        return self.model_dump(mode='json')


def resolve_scan_plan(*, target: str, target_type: str = 'path', profile: str | None = None,
                      scanners: list[str] | tuple[str, ...] | None = None, refs: list[str] | tuple[str, ...] | None = None,
                      settings: Settings | None = None, **overrides) -> ScanPlan:
    if profile is not None and profile not in PROFILES:
        raise ValueError(f'Unknown scan profile: {profile}')
    defaults = PROFILES[profile] if profile else ScanProfile(scanners=('git-history-patterns',) if target_type == 'mirror' else ('custom-patterns',))
    values = dict(target=target, target_type=target_type, profile=profile,
                  scanners=tuple(dict.fromkeys(scanners)) if scanners is not None else defaults.scanners,
                  discovery_provider=defaults.discovery_provider, history_policy=defaults.history_policy,
                  timeout_seconds=settings.scanner_timeout_seconds if settings else 300,
                  refs=tuple(dict.fromkeys(refs or ())), branch_policy='selected' if refs else 'default-only',
                  mode='history' if profile == 'history' else 'full')
    values.update({key: value for key, value in overrides.items() if value is not None})
    plan = ScanPlan(**values)
    validate_plan_scanners(plan, settings=settings)
    return plan


def validate_plan_scanners(plan: ScanPlan, *, settings: Settings | None = None) -> None:
    registry = get_registry()
    for name in plan.scanners:
        scanner = registry.get(name, settings=settings)
        if plan.target_type not in scanner.metadata.supported_targets:
            raise ValueError(f'Scanner {name} does not support {plan.target_type} targets')
        if plan.mode == 'history' and not scanner.metadata.supports_history:
            raise ValueError(f'Scanner {name} does not support history mode')
    if plan.discovery_provider:
        from orgscan.providers import available_domain_provider_names
        if plan.discovery_provider not in available_domain_provider_names():
            raise ValueError('Unsupported domain discovery provider')
