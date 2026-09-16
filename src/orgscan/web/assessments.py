"""Server-rendered operator pages. Inputs are already safe service projections."""
import html
import json
from urllib.parse import urlencode

from orgscan.reporting import _render_html_page
from orgscan.security_context import current_auth


def esc(value):
    return html.escape(str(value if value is not None else ''), quote=True)


def page(title, body, *, assessment=None):
    links = [
        ('Dashboard', '/dashboard'),
        ('Assessments', '/dashboard/assessments'),
        ('Findings', '/dashboard?high_signal_only=true'),
        ('Assets', '/dashboard/graph'),
        ('Discovery', '/dashboard/assessments'),
        ('Jobs', '/dashboard/queues/active-scans'),
        ('Reports', '/dashboard/assessments'),
        ('Settings', '/dashboard/settings/recon-tools'),
    ]
    nav = '<nav class="app-nav" aria-label="Main navigation">' + ''.join(
        f'<a class="nav-link{ " is-active" if url == "/dashboard" and title == "orgscan dashboard" else "" }" href="{url}">{label}</a>'
        for label, url in links
    ) + '</nav>'
    if assessment:
        identity = assessment['id']
        nav += '<div class="subnav" aria-label="Assessment navigation">' + ''.join(
            f'<a class="nav-link" href="/dashboard/assessments/{identity}/{slug}">{label}</a>'
            for slug, label in [
                ('overview', 'Overview'),
                ('targets', 'Targets'),
                ('discovery', 'Discovery'),
                ('recon-results', 'Discovery Results'),
                ('repositories', 'Repositories'),
                ('accounts', 'Accounts'),
                ('domains', 'Domains'),
                ('relationships', 'Relationships'),
                ('scans', 'Scans'),
                ('findings', 'Findings'),
                ('reports', 'Reports'),
                ('ai', 'Local AI'),
            ]
        ) + '</div>'
    header = (
        '<header class="page-header">'
        '<div>'
        '<p class="eyebrow">Operator workspace</p>'
        f'<h1>{esc(title)}</h1>'
        '</div>'
        '</header>'
    )
    return _render_html_page(title, nav + f'<div class="page-body">{header}{body}</div>')


def form(action, body, label='Save'):
    return f'<form class="stack-form" method="post" action="{esc(action)}">{body}<button type="submit">{esc(label)}</button></form>'


def input_field(name, label, value='', type='text'):
    return f'<label class="field"><span>{esc(label)}</span><input type="{type}" name="{name}" value="{esc(value)}"></label>'


def table(rows, columns):
    if not rows:
        return '<p class="empty-state">No results in this view. Add targets, run discovery, or adjust the filters.</p>'
    return (
        '<div class="table-shell">'
        '<table class="data-table"><thead><tr>' + ''.join('<th>' + esc(c) + '</th>' for c in columns) + '</tr></thead><tbody>' + ''.join(
            '<tr>' + ''.join('<td>' + esc(str(row.get(c, ''))) + '</td>' for c in columns) + '</tr>' for row in rows
        ) + '</tbody></table></div>'
    )


def paging(base, total, offset, limit=50):
    return (
        '<div class="pager">'
        + (f'<a class="pager-link" href="{esc(base + ("&" if "?" in base else "?") + "offset=" + str(max(0, offset - limit)))}">Previous</a>' if offset else '')
        + (f'<a class="pager-link" href="{esc(base + ("&" if "?" in base else "?") + "offset=" + str(offset + limit))}">Next</a>' if offset + limit < total else '')
        + '</div>'
    )


def index(payload, tenant, offset):
    rows = [{'Name': r['name'], 'Status': r['status'], 'Targets': r['counts']['targets'], 'Assets': r['counts']['assets'], 'Jobs': r['counts']['jobs'],
            'Last Activity': r['updated_at'], 'ID': r['id'], 'Owner': r['created_by'], 'Needs Attention': r.get('job_states', {}).get('failed', 0), 'Job States': r.get('job_states', {})} for r in payload['items']]
    body = f'<div class="action-bar"><a class="primary-action" href="/dashboard/assessments/new?{urlencode({"tenant": tenant})}">+ New Assessment</a></div>'
    body += table(rows, ['ID', 'Name', 'Status', 'Owner', 'Targets', 'Assets', 'Jobs', 'Job States', 'Needs Attention', 'Last Activity'])
    body += ''.join(f'<p class="assessment-link"><a href="/dashboard/assessments/{r["id"]}/overview">Open {esc(r["name"])}</a></p>' for r in payload['items'])
    return page('Assessments', body + paging('/dashboard/assessments?' + urlencode({'tenant': tenant}), payload['total'], offset))


def new(tenant):
    body = '<p class="intro-copy">Step 1 of 4: assessment information. Save now, add any number of target batches next.</p>'
    body += form('/dashboard/assessments/new', input_field('tenant', 'Tenant', tenant) + input_field('name', 'Name') +
        '<label class="field"><span>Description</span><textarea name="description" rows="4"></textarea></label>', 'Create assessment')
    return page('New Assessment', body)


def targets(assessment, payload, offset, result=None):
    identity = assessment['id']
    root = f'/dashboard/assessments/{identity}'
    body = '<p class="intro-copy">Step 2: paste locations, one per line. Configure GitHub hosts in Settings first. Use org:, user:, or repo: for bare identifiers.</p>'
    body += form(root + '/targets', '<label class="field"><span>Target locations</span><textarea name="text" rows="12" cols="100" placeholder="https://github.com/organization&#10;example.gov"></textarea></label>' +
        '<label class="field"><span>Format</span><select name="format"><option value="lines">One per line</option><option value="csv">CSV: type,location,connection,notes</option></select></label>', 'Add target batch')
    body += f'<form class="stack-form" method="post" enctype="multipart/form-data" action="{root}/targets/upload"><label class="field"><span>Upload target file</span><input type="file" name="upload" accept=".txt,.csv"></label><label class="field"><span>Format</span><select name="format"><option>lines</option><option value="csv">CSV</option></select></label><button type="submit">Upload</button></form>'
    body += f'<h2>Uploaded artifacts</h2><form class="stack-form" method="post" enctype="multipart/form-data" action="{root}/artifacts"><label class="field"><span>File or archive</span><input type="file" name="upload" required></label><button type="submit">Upload artifact</button></form>'
    if result:
        body += '<div class="result-panel"><p>' + esc(str(result['counts'])) + '</p>' + table(result['rows'], ['line', 'status', 'location', 'error', 'input']) + '</div>'
    rows = [{'ID': r['id'], 'Type': r['target_type'], 'Location': r['normalized_value'], 'Connection': r['connection_id'], 'Status': r['validation_status'], 'Visibility': (r.get('metadata_json') or {}).get('visibility_mode', 'inherit')} for r in payload['items']]
    body += table(rows, ['ID', 'Type', 'Location', 'Connection', 'Status', 'Visibility'])
    for r in payload['items']:
        if r['connection_id']:
            mode = (r.get('metadata_json') or {}).get('visibility_mode', 'inherit')
            controls = '<label class="field"><span>Target ' + str(r['id']) + ' visibility</span><select name="mode">' + ''.join('<option value="' + value + '" ' + ('selected' if mode == value else '') + '>' + label + '</option>' for value, label in (('inherit', 'inherit'), ('private', 'private'), ('public', 'public'))) + '</select></label>'
            body += form(root + f'/targets/{r["id"]}/visibility', controls, 'Save target visibility')
        body += form(root + f'/targets/{r["id"]}/remove', '', f'Remove target {r["id"]}')
    body += paging(root + '/targets', payload['total'], offset) + f'<p class="assessment-link"><a href="{root}/discovery">Next: Discovery options and review</a></p>'
    return page(assessment['name'] + ' — Targets', body, assessment=assessment)


def discovery(assessment, jobs, providers, profiles, saved=()):
    root = f'/dashboard/assessments/{assessment["id"]}'
    body = '<p class="intro-copy">Step 3/4: configure discovery, review saved targets, then launch. Jobs run in the configured background processing service.</p>'
    from orgscan.web.recon import STYLE, badge
    body = STYLE + body + '<p class="intro-copy">Passive profiles use public data sources. Standard adds DNS resolution and HTTP probing. Comprehensive allows explicit crawler, port and template selection.</p>'
    body += form(root + '/launch/discovery', '<label class="field"><span>Saved profile</span><select name="saved_profile"><option value="">Use options below</option>' + ''.join('<option>' + esc(row['name']) + '</option>' for row in saved) + '</select></label>' +
        '<div class="option-grid">' + ''.join('<label class="choice"><input type="checkbox" name="providers" value="' + esc(r['name']) + '"> ' + esc(r.get('display_name', r['name'])) + '</label>' for r in providers) + '</div>' +
        '<label class="choice checkbox"><input type="checkbox" name="active_authorized" value="true">I authorize active interaction with scoped assessment domains and their subdomains</label>' +
        '<label class="choice checkbox"><input type="checkbox" name="expand" value="true">Contributors, forks, commit identities</label>' +
        '<label class="choice checkbox"><input type="checkbox" name="members" value="true">Visible organization members</label>' +
        '<label class="choice checkbox"><input type="checkbox" name="contributor_repositories" value="true">Contributor-owned public repositories</label>' +
        '<label class="choice checkbox"><input type="checkbox" name="public_search" value="true">Public GitHub search intelligence</label>' +
        '<label class="choice checkbox"><input type="checkbox" name="include_private" value="true">Include private/internal repositories (connection must permit)</label>' +
        input_field('profile_name', 'Save these options as a reusable profile'),
        'Launch discovery')
    unavailable = assessment.get('discovery_profile', {}).get('unavailable_providers', [])
    if unavailable:
        body += '<div class="notice-inline">Unavailable tools explicitly excluded: ' + esc(', '.join(unavailable)) + '</div>'
    selected = set(assessment.get('discovery_profile', {}).get('providers', []))
    latest = {}
    for run in reversed(jobs['items']):
        latest.update(run.get('stages', {}))
    body += table([{'Provider': r['name'], 'Mode': r.get('mode', 'Passive'), 'Ready': r['status'] == 'ok', 'Selected': r['name'] in selected, 'Status': latest.get(r['name'], {}).get('status', 'Not run'), 'Result count': latest.get(r['name'], {}).get('result_count', 0)} for r in providers], ['Provider', 'Mode', 'Ready', 'Selected', 'Status', 'Result count'])
    body += job_table(root, jobs)
    return page(assessment['name'] + ' — Discovery', body, assessment=assessment)


def job_table(root, jobs):
    body = '<p class="muted">Job states: ' + esc(str(jobs['states'])) + '</p><p class="muted">Scheduled operations: ' + esc(str(jobs['total'])) + '</p>'
    if 'repository_jobs' in jobs:
        body += '<p class="muted">Repository jobs: ' + esc(str(jobs['repository_jobs']['completed'])) + ' / ' + esc(str(jobs['repository_jobs']['total'])) + ' completed</p><p class="muted">Findings by severity: ' + esc(str(jobs['findings'])) + '</p>'
    if 'repositories' in jobs:
        body += '<p class="muted">Repositories: ' + str(jobs['repositories']['completed']) + ' / ' + str(jobs['repositories']['total']) + ' completed (latest scan per repository)</p>'
    body += table(jobs['items'], ['id', 'kind', 'status', 'scan_job_id', 'attempts', 'failure_code', 'next_attempt_at', 'error'])
    for row in jobs['items']:
        if row.get('stages'):
            body += '<h3>Discovery job ' + str(row['id']) + '</h3>' + table([{'Stage': name, **state} for name, state in row['stages'].items()], ['Stage', 'status', 'version', 'input_count', 'result_count', 'started_at', 'completed_at'])
    body += form(root + '/pause', '', 'Pause future operations') + form(root + '/resume', '', 'Resume')
    for row in jobs['items']:
        if row['status'] == 'failed':
            body += form(root + f'/runs/{r["id"]}/retry', '', f'Retry run {r["id"]}')
    for row in jobs['items']:
        if row.get('scan_job_id'):
            body += f'<p class="assessment-link"><a href="/dashboard/scan-jobs/{row["scan_job_id"]}">Job {row["scan_job_id"]} details</a></p>'
    return body + paging(root + '/scans', jobs['total'], jobs.get('offset', 0), jobs.get('limit', 50)) + '<p class="assessment-link"><a href="">Refresh status</a></p>'


def assets(assessment, payload, kind, offset, filters=None):
    filters = {k: v for k, v in (filters or {}).items() if v is not None and v != ''}
    root = f'/dashboard/assessments/{assessment["id"]}'
    rows = []
    for link in payload['items']:
        e = link['entity']
        metadata = e.get('metadata_json') or {}
        rows.append({'ID': link['entity_id'], 'Location': metadata.get('remote_full_name') or metadata.get('login') or e.get('full_name') or e.get('username') or e.get('name'),
            'Included': link['included'], 'Source': link['source'], 'Visibility': metadata.get('visibility'), 'Archived': metadata.get('archived'),
            'Fork': metadata.get('fork'), 'Association': link['confidence'], 'Why': '; '.join(link['metadata_json'].get('reasons', [])), 'Connection': link['connection_id'], 'Sources': ', '.join(sorted(set(metadata.get('sources', [])))),
            'Updated': metadata.get('updated_at'), 'Scanned': e.get('scan_completed', False)})
    body = '<p class="intro-copy">Association confidence is deterministic. Analyst-confirmed decisions are recorded in finding triage.</p><form class="filter-form" method="get">' + ''.join(input_field(k, k, filters.get(k, '')) for k in (('search', 'search'), ('confidence', 'confidence'), ('source', 'source'), ('visibility', 'visibility'), ('updated_after', 'updated_after'), ('updated_before', 'updated_before'))) + '<button type="submit">Filter</button></form>'
    for k in ('archived', 'fork', 'scanned') if kind == 'repositories' else ():
        body += '<label class="field"><span>' + k + '</span><select name="' + k + '">' + ''.join('<option value="' + value + '" ' + ('selected' if filters.get(k) == selected else '') + '>' + label + '</option>' for value, label, selected in (('', 'Any', ''), ('true', 'True', 'true'), ('false', 'False', 'false'))) + '</select></label>'
    columns = {'repositories': ['ID', 'Location', 'Connection', 'Included', 'Sources', 'Visibility', 'Archived', 'Fork', 'Association', 'Why', 'Updated', 'Scanned'], 'accounts': ['ID', 'Location', 'Connection', 'Source', 'Association', 'Updated'], 'domains': ['ID', 'Location', 'Connection', 'Association', 'Updated'], 'relationships': ['ID', 'From', 'Relation', 'To', 'Confidence']}[kind]
    body += table(rows, columns)
    for row in rows:
        body += f'<p class="assessment-link"><a href="{root}/relationships?entity_type=' + {'repositories': 'repository', 'accounts': 'account', 'domains': 'domain'}[kind] + '&entity_id=' + str(row['ID']) + '">Explore ' + esc(str(row['Location'])) + '</a></p>'
    if kind == 'repositories':
        hidden = ''.join(input_field(k, k, str(v).lower() if isinstance(v, bool) else v, type='hidden') for k, v in filters.items())
        page_ids = ','.join(str(row['ID']) for row in rows)
        if page_ids:
            body += form(root + '/selection', hidden + input_field('ids', '', page_ids, type='hidden') + input_field('included', '', 'true', type='hidden'), 'Include page')
            body += form(root + '/selection', hidden + input_field('ids', '', page_ids, type='hidden') + input_field('included', '', 'false', type='hidden'), 'Exclude page')
        body += form(root + '/selection', hidden + input_field('included', '', 'true', type='hidden'), 'Include filtered')
        body += form(root + '/selection', hidden + input_field('included', '', 'false', type='hidden'), 'Exclude filtered')
        body += form(root + '/selection', hidden + input_field('included', '', 'false', type='hidden') + input_field('selection_mode', '', 'checked', type='hidden'), 'Clear scan scope')
        choices = input_field('selection_mode', '', 'checked', type='hidden')
        choices += ''.join('<label class="choice"><input type="checkbox" name="selected_ids" value="' + str(row['ID']) + '">' + esc(str(row['Location'])) + '</label> ' for row in rows)
        choices += '<label class="field"><span>Selected repositories</span><select name="included"><option value="true">Include</option><option value="false">Exclude</option></select></label>'
        if rows:
            body += form(root + '/selection', choices, 'Apply to selected repositories')
        body += form(root + '/selection', hidden + '<label class="field"><span>Repository IDs</span><input name="ids"></label><select name="included"><option value="true">Include</option><option value="false">Exclude</option></select>', 'Apply custom selection')
    body += paging(root + '/' + kind + '?' + urlencode(filters), payload['total'], offset)
    return page(assessment['name'] + ' — ' + kind.title(), body, assessment=assessment)


def scans(assessment, jobs, inventory, profiles):
    root = f'/dashboard/assessments/{assessment["id"]}'
    controls = '<label class="field"><span>Profile</span><select name="profile">' + ''.join(f'<option>{esc(p)}</option>' for p in profiles if p not in ('osint-only', 'domain-only')) + '</select></label>'
    for row in inventory:
        controls += f'<label class="choice"><input type="checkbox" name="scanners" value="{esc(row["name"])}" ' + ('' if row['readiness']['ready'] else 'disabled') + '>' + esc(row['name']) + ' — ' + esc(str(row['readiness']['ready'])) + '</label>'
    controls += '<label class="field"><span>Branches</span><select name="branch_policy"><option>default-only</option><option>selected</option><option>all</option><option>tracked</option></select></label>'
    controls += input_field('refs', 'Selected refs (comma separated)') + '<label class="field"><span>Mode</span><select name="mode"><option value="">Profile default</option><option>full</option><option>incremental</option><option>history</option></select></label>'
    body = '<p class="intro-copy">Explicit scanner selections override profile scanners. Unavailable tools fail validation; they are never silently run. Review included repositories before launch.</p>'
    body += form(root + '/launch/scan', controls, 'Review scan') + job_table(root, jobs)
    return page(assessment['name'] + ' — Scans', body, assessment=assessment)


def findings(assessment, payload, filters=None):
    filters = {k: v for k, v in (filters or {}).items() if v is not None and v != ''}
    body = '<form class="filter-form" method="get">' + ''.join(input_field(field, field, filters.get(field, '')) for field in ('severity', 'confidence', 'status', 'source_tool', 'category', 'repository_id', 'domain_id', 'account_id', 'lifecycle_state')) + '<button type="submit">Filter</button></form>'
    body += table(payload['items'], ['id', 'severity', 'title', 'repository_id', 'confidence', 'observed_by', 'first_seen_at', 'last_seen_at', 'lifecycle_state'])
    body += ''.join(f'<p class="assessment-link"><a href="/dashboard/assessments/{assessment["id"]}/findings/{r["id"]}">Finding {r["id"]}: {esc(r["title"])}</a></p>' for r in payload['items'])
    body += paging(f'/dashboard/assessments/{assessment["id"]}/findings?' + urlencode(filters), payload['total'], payload['offset'], payload['limit'])
    return page(assessment['name'] + ' — Findings', body, assessment=assessment)


def graph(assessment, payload, filters=None):
    filters = {k: v for k, v in (filters or {}).items() if v is not None}
    root = f'/dashboard/assessments/{assessment["id"]}/relationships'
    body = '<form class="filter-form" method="get">' + ''.join(input_field(k, k, filters.get(k, '')) for k in ('entity_type', 'entity_id', 'relation_type', 'confidence')) + '<button type="submit">Filter</button></form>'
    body += table(payload['edges'], ['from', 'relation_type', 'to', 'confidence', 'source', 'provenance', 'first_seen', 'last_seen'])
    body += '<h2>Explore connected assets</h2>'
    for node in payload['nodes']:
        body += '<p class="assessment-link"><a href="' + esc(root + '?' + urlencode({'entity_type': node['entity_type'], 'entity_id': node['entity_id']})) + '">' + esc(node['label']) + '</a> (' + esc(node['entity_type']) + ')</p>'
        if node['entity_type'] == 'repository':
            body += f'<a href="/dashboard/assessments/{assessment["id"]}/findings?repository_id={node["entity_id"]}">Repository findings</a>'
    body += paging(root + '?' + urlencode(filters), payload['total'], payload['offset'], payload['limit'])
    body += form(f'/dashboard/assessments/{assessment["id"]}/launch/ai', '<input type="hidden" name="purpose" value="correlations">', 'Explain relationships with Local AI')
    return page(assessment['name'] + ' — Relationships', body, assessment=assessment)


def connections(payload, tenant):
    body = '<p class="intro-copy">Tokens are provisioned as environment variables in API and worker processes. Enter only the variable name; tokens are never stored here.</p>'
    body += table(payload['items'], ['id', 'name', 'connection_type', 'web_base_url', 'api_base_url', 'enabled', 'last_test_status', 'metadata_json'])
    auth = current_auth.get()
    if auth and auth.allows_role('admin'):
        body += form('/dashboard/settings/github', input_field('tenant', 'Tenant', tenant) + input_field('name', 'Name') +
            '<label class="field"><span>Connection type</span><select name="connection_type"><option>github</option><option>ghes</option></select></label>' + input_field('web_base_url', 'Web URL', 'https://github.com') +
            input_field('api_base_url', 'API URL', 'https://api.github.com') + input_field('credential_env', 'Credential environment reference') +
            '<label class="choice checkbox"><input type="checkbox" name="allow_private" value="true">Permit explicitly selected private/internal scope</label>', 'Add GitHub connection')
        for row in payload['items']:
            body += '<h2>' + esc(row['name']) + '</h2>'
            controls = input_field('tenant', 'Tenant', tenant, type='hidden') + input_field('name', 'Name', row['name']) + input_field('credential_env', 'Credential reference', row['credential_env'])
            for key, label in (('enabled', 'Enabled'), ('allow_private', 'Permit explicitly selected private/internal scope')):
                controls += f'<label class="choice checkbox"><input type="checkbox" name="{key}" value="true" ' + ('checked' if row[key] else '') + '>' + label + '</label>'
            body += form(f'/dashboard/settings/github/{row["id"]}/edit', controls, 'Save connection')
            body += form(f'/dashboard/settings/github/{row["id"]}/test', input_field('tenant', 'Tenant', tenant, type='hidden'), 'Test connection')
        body += '<p class="intro-copy">To change an endpoint, add a connection and import targets for that host. Existing targets retain their original connection.</p>'
    body += '<p class="assessment-link"><a href="/dashboard/settings/local-ai">Local AI settings</a></p>'
    return page('GitHub Connections', body)


def local_ai(config, tenant):
    body = '<p class="intro-copy">Optional local AI. Suggestions never change deterministic evidence or finding decisions.</p>'
    body += '<p class="muted">Status: ' + esc(config.get('status', 'Not tested')) + ' · Protected data: disabled · Source code: disabled</p>'
    controls = input_field('tenant', 'Tenant', tenant) + input_field('base_url', 'Ollama endpoint', config['base_url'])
    controls += input_field('model', 'Installed model', config['model']).replace('<input ', '<input list="installed-models" ', 1)
    controls += '<datalist id="installed-models">' + ''.join('<option value="' + esc(row['name']) + '">' for row in config.get('models', [])) + '</datalist>'
    controls += '<label class="choice checkbox"><input type="checkbox" name="enabled" value="true" ' + ('checked' if config['enabled'] else '') + '>Enable Local AI</label>'
    controls += '<button name="action" value="test">Save and test connection</button>'
    body += form('/dashboard/settings/local-ai', controls, 'Save settings')
    body += table(config.get('models', []), ['name', 'size'])
    return page('Local AI settings', body)


def advice(assessment, payload):
    body = '<p class="intro-copy">AI Suggested: advisory output only. Deterministic confidence remains authoritative. Results describe bounded input at generation time.</p>'
    for purpose in ('summary', 'correlations', 'triage', 'repository', 'finding'):
        body += form(f'/dashboard/assessments/{assessment["id"]}/launch/ai', f'<input type="hidden" name="purpose" value="{purpose}">' + (input_field('entity_id', 'Repository ID' if purpose == 'repository' else 'Entity ID', type='text')), 'Request ' + purpose.title() + ' advice')
    for row in payload['items']:
        body += '<h2>' + esc(row['purpose']) + ' — AI Suggested</h2>'
        body += '<p class="muted">' + esc(row['provider']) + ' / ' + esc(row['model']) + ' · ' + esc(row['created_at']) + ' · ' + esc(row['policy_version']) + '</p>'
        body += table([row['output_json']], ['classification', 'confidence', 'explanation', 'suggested_tags'])
    return page(assessment['name'] + ' — Local AI', body, assessment=assessment)


def edit_assessment(assessment):
    controls = input_field('name', 'Assessment name', assessment['name'])
    controls += '<label class="field"><span>Description</span><textarea name="description">' + esc(assessment['description']) + '</textarea></label>'
    controls += '<label class="field"><span>Status</span><select name="status"><option value="">Keep current: ' + esc(assessment['status']) + '</option>' + ''.join(f'<option value="{state}" ' + ('selected' if state == assessment['status'] else '') + '>' + state + '</option>' for state in ('draft', 'active', 'archived')) + '</select></label>'
    return '<details class="editor-panel"><summary>Edit assessment</summary>' + form(f'/dashboard/assessments/{assessment["id"]}/edit', controls) + '</details>'


def scan_review(assessment, preview):
    root = f'/dashboard/assessments/{assessment["id"]}'
    body = f'<p class="intro-copy">{preview["repositories"]} repositories · {len(preview["scanners"])} scanners · History ' + ('enabled' if preview['history_enabled'] else 'disabled') + '</p>'
    body += '<p class="muted">Scanners: ' + esc(', '.join(preview['scanners'])) + '</p>'
    controls = input_field('action', '', 'confirmed', type='hidden')
    for key, value in preview['options'].items():
        if value is None:
            continue
        if key == 'refs':
            value = ','.join(value)
        for item in value if isinstance(value, list) else [value]:
            controls += input_field(key, '', item, type='hidden')
    body += form(root + '/launch/scan', controls, 'Start scan')
    return page(assessment['name'] + ' — Review scan', body, assessment=assessment)


def discovery_review(assessment, review):
    from orgscan.web.recon import STYLE, badge
    options = review['options']
    hidden = ''
    for key, value in options.items():
        if key == 'name':
            key = 'profile'
        if isinstance(value, bool):
            value = 'true' if value else 'false'
        for item in value if isinstance(value, list) else [value]:
            hidden += '<input type="hidden" name="' + esc(key) + '" value="' + esc(str(item)) + '">'
    body = STYLE + '<h2>Review active validation</h2><p class="intro-copy">Targets: ' + str(review['targets']) + ' · Previously observed HTTP services: ' + str(review['http_endpoints']) + '</p><p class="muted">Counts can change as upstream providers refresh.</p>'
    body += '<h3>Active tools</h3>' + ''.join(badge(tool, 'recon-active') for tool in review['active_tools'])
    body += '<p class="intro-copy">Crawling, port discovery and template checks interact with targets. Nuclei uses only configured local templates. Third-party references are not authorized targets.</p>'
    body += form('/dashboard/assessments/' + str(assessment['id']) + '/launch/discovery', hidden + '<input type="hidden" name="action" value="confirmed">', 'Start Active Validation')
    return page('Review active validation', body, assessment=assessment)


# Backward-compatible export kept in place for templates and API routes.
__all__ = [
    'esc', 'page', 'form', 'input_field', 'table', 'paging', 'index', 'new', 'targets',
    'discovery', 'job_table', 'assets', 'scans', 'findings', 'graph', 'connections',
    'local_ai', 'advice', 'edit_assessment', 'scan_review', 'discovery_review',
]


# NOTE: Legacy uses below keep the surrounding function names working even when rendered
# from older templates; these are intentionally thin wrappers around the styles above.


# file intentionally kept with the same public behavior as before.
																																																																																																		      
