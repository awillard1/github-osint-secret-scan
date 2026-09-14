"""Frozen keyless Phase 23 repair. No application imports or secret extraction.

An opaque copied password is indistinguishable from ordinary prose without its
key/context. Quarantine untrusted text/JSON on affected records instead of guessing.
The operation is bounded per column and never traverses attacker-controlled JSON.
"""
import re
import hashlib

REDACTED = '<redacted>'
DIGESTS = {'fingerprint', 'normalized_hash', 'observation_fingerprint', 'commit_sha'}
ENUMS = {
    'severity': {'info', 'low', 'medium', 'high', 'critical'},
    'confidence': {'unverified', 'heuristic', 'likely', 'verified'},
    'source_class': {'internal', 'free', 'paid'},
    'status': {'open', 'triaged', 'resolved', 'suppressed', 'false_positive', 'accepted_risk'},
    'lifecycle_state': {'NEW', 'OPEN', 'TRIAGED', 'REVIEWING', 'SUPPRESSED', 'CONFIRMED', 'REMEDIATED', 'REGRESSED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'},
    'triage_state': {'new', 'in_review', 'confirmed', 'dismissed'},
    'from_state': {'NEW', 'OPEN', 'TRIAGED', 'REVIEWING', 'SUPPRESSED', 'CONFIRMED', 'REMEDIATED', 'REGRESSED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'},
    'to_state': {'NEW', 'OPEN', 'TRIAGED', 'REVIEWING', 'SUPPRESSED', 'CONFIRMED', 'REMEDIATED', 'REGRESSED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'},
}
# Polymorphic relationship identifiers are application references, not evidence.
REFERENCES = {'entity_id', 'from_entity_id', 'to_entity_id'}
TYPES = {'finding', 'evidence', 'organization', 'repository', 'domain', 'account'}


def repair_values(row):
    changed = {}
    for key, value in row.items():
        if not isinstance(value, (str, dict, list)):
            continue
        if key in DIGESTS and isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{40,64}', value):
            continue
        if key in REFERENCES:
            continue
        if key == 'relation_type' and isinstance(value, str):
            # Labels participate in a uniqueness constraint. Distinct legacy
            # edges must not collapse into one redacted label during repair.
            if not re.fullmatch(r'phase24-[0-9a-f]{56}', value):
                changed[key] = 'phase24-' + hashlib.sha256(value.encode()).hexdigest()[:56]
            continue
        if key in {'entity_type', 'from_entity_type', 'to_entity_type'} and value in TYPES:
            continue
        if key in ENUMS and isinstance(value, str) and value in ENUMS[key]:
            continue
        replacement = {} if isinstance(value, dict) else [] if isinstance(value, list) else REDACTED if value else value
        if value != replacement:
            changed[key] = replacement
    return changed
