"""SARIF 2.1.0 adapter for canonical issues with safely mapped file locations."""
from urllib.parse import quote
from orgscan import __version__
from orgscan.reports.redaction import redact

SCHEMA = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json'


def build_sarif(findings):
    findings = redact(findings)
    rule_ids = sorted({f'{row["source_tool"]}/{row["category"]}' for row in findings})
    rules = [{'id': identity, 'shortDescription': {'text': identity}} for identity in rule_ids]
    results = []
    for row in findings:
        identity = f'{row["source_tool"]}/{row["category"]}'
        result = {'ruleId': identity, 'ruleIndex': rule_ids.index(identity),
            'level': {'critical':'error','high':'error','medium':'warning'}.get(row['severity'],'note'),
            'message': {'text': f'{row["title"]}\n{row["description"]}'},
            'partialFingerprints': {'orgscan/v1': row['fingerprint']},
            'properties': {key: row.get(key) for key in ('id','severity','confidence','risk_score','lifecycle_state',
                'first_seen_at','last_seen_at','remediated_at','regressed_at','regression_count','repository','evidence')}}
        locations = []
        for item in row.get('evidence', []):
            if not item.get('path'):
                continue
            physical = {'artifactLocation': {'uri': quote(item['path'], safe='/')}}
            if isinstance(item.get('line_start'), int) and item['line_start'] > 0:
                physical['region'] = {'startLine': item['line_start']}
                if isinstance(item.get('line_end'), int) and item['line_end'] >= item['line_start']:
                    physical['region']['endLine'] = item['line_end']
            location = {'physicalLocation': physical}
            if location not in locations:
                locations.append(location)
        if locations:
            result['locations'] = locations
        if row.get('lifecycle_state') in {'FALSE_POSITIVE','SUPPRESSED','ACCEPTED_RISK'}:
            result['suppressions'] = [{'kind':'external','status':'accepted','justification':row['lifecycle_state']}]
        results.append(result)
    return {'$schema':SCHEMA,'version':'2.1.0','runs':[{'tool':{'driver':{'name':'orgscan','version':__version__,'rules':rules}},'results':results}]}
