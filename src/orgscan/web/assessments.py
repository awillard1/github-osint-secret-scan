"""Server-rendered operator pages. Inputs are already safe service projections."""
import html
import json
from urllib.parse import urlencode
from orgscan.reporting import _render_html_page
from orgscan.security_context import current_auth


def esc(value):return html.escape(str(value if value is not None else ''),quote=True)


def page(title,body,*,assessment=None):
    links=[('Dashboard','/dashboard'),('Assessments','/dashboard/assessments'),('Findings','/dashboard?high_signal_only=true'),
        ('Assets','/dashboard/graph'),('Discovery','/dashboard/assessments'),('Jobs','/dashboard/queues/active-scans'),
        ('Reports','/dashboard/assessments'),('Settings','/dashboard/settings/recon-tools')]
    nav='<nav>'+' · '.join(f'<a href="{url}">{label}</a>' for label,url in links)+'</nav>'
    if assessment:
        identity=assessment['id']
        nav+='<p><a href="/dashboard/assessments">Assessments</a> / '+esc(assessment['name'])+'</p>'
        nav+='<nav>'+' · '.join(f'<a href="/dashboard/assessments/{identity}/{slug}">{label}</a>' for slug,label in
            [('overview','Overview'),('targets','Targets'),('discovery','Discovery'),('recon-results','Discovery Results'),('repositories','Repositories'),
             ('accounts','Accounts'),('domains','Domains'),('relationships','Relationships'),('scans','Scans'),('findings','Findings'),('reports','Reports'),('ai','Local AI')])+'</nav>'
    return _render_html_page(title,nav+f'<h1>{esc(title)}</h1>'+body)


def form(action,body,label='Save'):
    return f'<form method="post" action="{esc(action)}">{body}<button type="submit">{esc(label)}</button></form>'


def input_field(name,label,value='',type='text'):
    return f'<label>{esc(label)} <input type="{type}" name="{name}" value="{esc(value)}"></label> '


def table(rows,columns):
    if not rows:return '<p>No results in this view. Add targets, run discovery, or adjust the filters.</p>'
    return '<table><thead><tr>'+''.join('<th>'+esc(c)+'</th>' for c in columns)+'</tr></thead><tbody>'+''.join(
        '<tr>'+''.join('<td>'+esc(row.get(c,''))+'</td>' for c in columns)+'</tr>' for row in rows)+'</tbody></table>'


def paging(base,total,offset,limit=50):
    return ('<a href="'+esc(base+('&' if '?' in base else '?')+'offset='+str(max(0,offset-limit)))+'">Previous</a> ' if offset else '')+(
        '<a href="'+esc(base+('&' if '?' in base else '?')+'offset='+str(offset+limit))+'">Next</a>' if offset+limit<total else '')


def index(payload,tenant,offset):
    rows=[{'Name':r['name'],'Status':r['status'],'Targets':r['counts']['targets'],'Assets':r['counts']['assets'],'Jobs':r['counts']['jobs'],
           'Last Activity':r['updated_at'],'ID':r['id'],'Owner':r['created_by'],'Needs Attention':r.get('job_states',{}).get('failed',0),'Job States':r.get('job_states',{})} for r in payload['items']]
    body=f'<a href="/dashboard/assessments/new?{urlencode({"tenant":tenant})}">+ New Assessment</a>'
    body+=table(rows,['ID','Name','Status','Owner','Targets','Assets','Jobs','Job States','Needs Attention','Last Activity'])
    body+=''.join(f'<p><a href="/dashboard/assessments/{r["id"]}/overview">Open {esc(r["name"])}</a></p>' for r in payload['items'])
    return page('Assessments',body+paging('/dashboard/assessments?'+urlencode({'tenant':tenant}),payload['total'],offset))


def new(tenant):
    body='<p>Step 1 of 4: assessment information. Save now, add any number of target batches next.</p>'
    body+=form('/dashboard/assessments/new',input_field('tenant','Tenant',tenant)+input_field('name','Name')+
        '<label>Description<textarea name="description" rows="4"></textarea></label>','Create assessment')
    return page('New Assessment',body)


def targets(assessment,payload,offset,result=None):
    identity=assessment['id'];root=f'/dashboard/assessments/{identity}'
    body='<p>Step 2: paste locations, one per line. Configure GitHub hosts in Settings first. Use org:, user:, or repo: for bare identifiers.</p>'
    body+=form(root+'/targets', '<label>Target locations<textarea name="text" rows="12" cols="100" placeholder="https://github.com/organization&#10;example.gov"></textarea></label>'+
        '<label>Format<select name="format"><option value="lines">One per line</option><option value="csv">CSV: type,location,connection,notes</option></select></label>','Add target batch')
    body+=f'<form method="post" enctype="multipart/form-data" action="{root}/targets/upload"><input type="file" name="upload" accept=".txt,.csv"><select name="format"><option>lines</option><option>csv</option></select><button>Import file</button></form>'
    body+=f'<h2>Uploaded artifacts</h2><form method="post" enctype="multipart/form-data" action="{root}/artifacts"><label>File or archive<input type="file" name="upload" required></label><button>Add artifact</button></form>'
    if result:
        body+='<p>'+esc(result['counts'])+'</p>'+table(result['rows'],['line','status','location','error','input'])
    rows=[{'ID':r['id'],'Type':r['target_type'],'Location':r['normalized_value'],'Connection':r['connection_id'],'Status':r['validation_status'],'Visibility':(r.get('metadata_json') or {}).get('visibility_mode','inherit')} for r in payload['items']]
    body+=table(rows,['ID','Type','Location','Connection','Status','Visibility'])
    for r in payload['items']:
        if r['connection_id']:
            mode=(r.get('metadata_json') or {}).get('visibility_mode','inherit')
            controls='<label>Target '+str(r['id'])+' visibility<select name="mode">'+''.join('<option value="'+value+'" '+('selected' if mode==value else '')+'>'+label+'</option>' for value,label in (('inherit','Use recon profile'),('public','Public only'),('private','Include authorized private/internal')))+'</select></label>'
            body+=form(root+f'/targets/{r["id"]}/visibility',controls,'Save target visibility')
        body+=form(root+f'/targets/{r["id"]}/remove','',f'Remove target {r["id"]}')
    body+=paging(root+'/targets',payload['total'],offset)+f'<p><a href="{root}/discovery">Next: Discovery options and review</a></p>'
    return page(assessment['name']+' — Targets',body,assessment=assessment)


def discovery(assessment,jobs,providers,profiles,saved=()):
    root=f'/dashboard/assessments/{assessment["id"]}'
    body='<p>Step 3/4: configure discovery, review saved targets, then launch. Jobs run in the configured background processing service.</p>'
    from orgscan.web.recon import STYLE,badge
    body=STYLE+body+'<p>Passive profiles use public data sources. Standard adds DNS resolution and HTTP probing. Comprehensive allows explicit crawler, port and template selection. Active components require authorization below.</p><p><a href="/dashboard/settings/recon-tools">Manage and install recon tools</a> · <a href="'+root+'/recon-results">View discovery results</a></p>'
    body+=form(root+'/launch/discovery','<label>Saved profile<select name="saved_profile"><option value="">Use options below</option>'+''.join('<option>'+esc(row['name'])+'</option>' for row in saved)+'</select></label><select name="profile">'+''.join(f'<option value="{esc(p)}">{esc(p.replace("-"," " ).title())}</option>' for p in profiles)+'</select>'+
        '<div class="recon-grid">'+''.join('<div class="recon-choice"><label><input type="checkbox" name="providers" value="'+esc(r['name'])+'"> '+esc(r.get('display_name',r['name']))+'</label>'+badge(r.get('mode','Passive'),'recon-passive' if r.get('mode','Passive')=='Passive' else 'recon-active')+' '+badge('Ready' if r['status']=='ok' else 'Needs attention','recon-ready' if r['status']=='ok' else 'recon-missing')+'</div>' for r in providers if r['name'] not in ('all','all-enriched','github-search','projectdiscovery'))+'</div>'+
        '<label><input type="checkbox" name="active_authorized" value="true">I authorize active interaction with scoped assessment domains and their subdomains</label><label><input type="checkbox" name="run_available_only" value="true">Run available tools only; record unavailable selections</label>'+
        '<label><input type="checkbox" name="expand" value="true">Contributors, forks, commit identities</label>'+
        '<label><input type="checkbox" name="members" value="true">Visible organization members</label>'+
        '<label><input type="checkbox" name="contributor_repositories" value="true">Contributor-owned public repositories</label>'+
        '<label><input type="checkbox" name="public_search" value="true">Public GitHub search intelligence</label>'+
        '<label><input type="checkbox" name="include_private" value="true">Include private/internal repositories (connection must permit)</label>'+input_field('profile_name','Save these options as')+'<button name="action" value="save_profile">Save recon profile</button><button name="action" value="install_missing">Install Missing</button>','Start discovery')
    unavailable=assessment.get('discovery_profile',{}).get('unavailable_providers',[])
    if unavailable:body+='<div class="recon-notice">Unavailable tools explicitly excluded: '+esc(', '.join(unavailable))+'</div>'
    selected=set(assessment.get('discovery_profile',{}).get('providers',[]))
    latest={}
    for run in reversed(jobs['items']):latest.update(run.get('stages',{}))
    body+=table([{'Provider':r['name'],'Mode':r.get('mode','Passive'),'Ready':r['status']=='ok','Selected':r['name'] in selected,'Status':latest.get(r['name'],{}).get('status','Not run'),'Result Count':latest.get(r['name'],{}).get('result_count','')} for r in providers if r['name'] not in ('all','all-enriched','github-search')],['Provider','Mode','Ready','Selected','Status','Result Count'])
    body+=job_table(root,jobs)
    return page(assessment['name']+' — Discovery',body,assessment=assessment)


def job_table(root,jobs):
    body='<p>Job states: '+esc(jobs['states'])+'</p><p>Scheduled operations: '+esc(jobs['total'])+'</p>'
    if 'repository_jobs' in jobs:
        body+='<p>Repository jobs: '+esc(jobs['repository_jobs']['completed'])+' / '+esc(jobs['repository_jobs']['total'])+' completed</p><p>Findings by severity: '+esc(jobs['findings'])+'</p>'
    if 'repositories' in jobs:body+='<p>Repositories: '+str(jobs['repositories']['completed'])+' / '+str(jobs['repositories']['total'])+' completed (latest scan per repository)</p>'
    body+=table(jobs['items'],['id','kind','status','scan_job_id','attempts','failure_code','next_attempt_at','error'])
    for row in jobs['items']:
        if row.get('stages'):
            body+='<h3>Discovery job '+str(row['id'])+'</h3>'+table([{'Stage':name,**state} for name,state in row['stages'].items()],['Stage','status','version','input_count','result_count','started_at','completed_at','error'])
    body+=form(root+'/pause','','Pause future operations')+form(root+'/resume','','Resume')
    for r in jobs['items']:
        if r['status']=='failed':body+=form(root+f'/runs/{r["id"]}/retry','',f'Retry run {r["id"]}')
    for row in jobs['items']:
        if row.get('scan_job_id'):body+=f'<p><a href="/dashboard/scan-jobs/{row["scan_job_id"]}">Job {row["scan_job_id"]} details</a></p>'
    return body+paging(root+'/scans',jobs['total'],jobs.get('offset',0),jobs.get('limit',50))+'<p><a href="">Refresh status</a></p>'


def assets(assessment,payload,kind,offset,filters=None):
    filters={k:v for k,v in (filters or {}).items() if v is not None and v!=""}
    root=f'/dashboard/assessments/{assessment["id"]}'
    rows=[]
    for link in payload['items']:
        e=link['entity'];metadata=e.get('metadata_json') or {}
        rows.append({'ID':link['entity_id'],'Location':metadata.get('remote_full_name') or metadata.get('login') or e.get('full_name') or e.get('username') or e.get('name'),
            'Included':link['included'],'Source':link['source'],'Visibility':metadata.get('visibility'), 'Archived':metadata.get('archived'),
            'Fork':metadata.get('fork'),'Association':link['confidence'],'Why':'; '.join(link['metadata_json'].get('reasons',[])),'Connection':link['connection_id'],'Sources':', '.join(sorted(set(link['metadata_json'].get('sources',[]))|set(e.get('discovery_sources',[])))),'First Seen':link['metadata_json'].get('first_seen',link['created_at']),'Last Seen':link['metadata_json'].get('last_seen',link['updated_at']),'Repositories':metadata.get('repositories'),'Contributions':metadata.get('contributions'),'Email Domains':metadata.get('email_domains'),'HTTP Status':link['metadata_json'].get('http_status','Not observed'),
            'Updated':metadata.get('updated_at'),'Scanned':e.get('scan_completed',False)})
    body='<p>Association confidence is Deterministic. Analyst Confirmed decisions are recorded in finding triage.</p><form method="get">'+''.join(input_field(k,k,filters.get(k,'')) for k in (('search','confidence','source','visibility','updated_after','updated_before') if kind=='repositories' else ('search','confidence','source')))
    for k in ('archived','fork','scanned') if kind=='repositories' else ():
        body+='<label>'+k+'<select name="'+k+'">'+''.join('<option value="'+value+'" '+('selected' if filters.get(k)==selected else '')+'>'+label+'</option>' for value,label,selected in (('','Any',None),('true','Yes',True),('false','No',False)))+'</select></label>'
    body+='<button>Filter</button></form>'
    columns={'repositories':['ID','Location','Connection','Included','Sources','Visibility','Archived','Fork','Association','Why','Updated','Scanned'],'accounts':['ID','Location','Connection','Sources','Repositories','Contributions','Email Domains','Association','Why'],'domains':['ID','Location','Sources','HTTP Status','First Seen','Last Seen','Association','Why']}
    body+=table(rows,columns[kind])
    for row in rows:body+=f'<a href="{root}/relationships?entity_type='+{'repositories':'repository','accounts':'account','domains':'domain'}[kind]+'&entity_id='+str(row['ID'])+'">Explore '+esc(row['Location'])+'</a> '
    if kind=='repositories':
        hidden=''.join(input_field(k,k,str(v).lower() if isinstance(v,bool) else v,type='hidden') for k,v in filters.items())
        page_ids=','.join(str(row['ID']) for row in rows)
        if page_ids:
            body+=form(root+'/selection',hidden+input_field('ids','',page_ids,type='hidden')+input_field('included','','true',type='hidden'),'Include page')
            body+=form(root+'/selection',hidden+input_field('ids','',page_ids,type='hidden')+input_field('included','','false',type='hidden'),'Exclude page')
        body+=form(root+'/selection',hidden+input_field('included','','true',type='hidden'),'Include filtered')
        body+=form(root+'/selection',hidden+input_field('included','','false',type='hidden'),'Exclude filtered')
        body+=form(root+'/selection',input_field('included','','false',type='hidden'),'Clear scan scope')
        choices=input_field('selection_mode','','checked',type='hidden')
        choices+=''.join('<label><input type="checkbox" name="selected_ids" value="'+str(row['ID'])+'">'+esc(row['Location'])+'</label> ' for row in rows)
        choices+='<label>Selected repositories<select name="included"><option value="true">Include</option><option value="false">Exclude</option></select></label>'
        if rows:body+=form(root+'/selection',choices,'Apply to selected repositories')
        body+=form(root+'/selection',hidden+'<label>Repository IDs (comma separated; leave empty for all filtered)<input name="ids"></label><select name="included"><option value="true">Include</option><option value="false">Exclude</option></select>','Apply selection')
    body+=paging(root+'/'+kind+'?'+urlencode(filters),payload['total'],offset)
    return page(assessment['name']+' — '+kind.title(),body,assessment=assessment)


def scans(assessment,jobs,inventory,profiles):
    root=f'/dashboard/assessments/{assessment["id"]}'
    controls='<label>Profile<select name="profile">'+''.join(f'<option>{esc(p)}</option>' for p in profiles if p not in ('osint-only','domain-only'))+'</select></label>'
    for row in inventory:
        controls+=f'<label><input type="checkbox" name="scanners" value="{esc(row["name"])}" '+('' if row['readiness']['ready'] else 'disabled')+f'>{esc(row["name"])} — {esc(row["readiness"]["status"])}</label> '
    controls+='<label>Branches<select name="branch_policy"><option>default-only</option><option>selected</option><option>all</option><option>tracked</option></select></label>'
    controls+=input_field('refs','Selected refs (comma separated)')+'<label>Mode<select name="mode"><option value="">Profile default</option><option>full</option><option>incremental</option><option>history</option></select></label>'
    body='<p>Explicit scanner selections override profile scanners. Unavailable tools fail validation; they are never silently run. Review included repositories before launch.</p>'
    body+=form(root+'/launch/scan',controls,'Review scan')+job_table(root,jobs)
    return page(assessment['name']+' — Scans',body,assessment=assessment)


def findings(assessment,payload,filters=None):
    filters={k:v for k,v in (filters or {}).items() if v is not None and v!=""}
    body='<form method="get">'+''.join(input_field(field,field,filters.get(field,'')) for field in ('severity','confidence','status','source_tool','category','repository_id','domain_id','account_id','organization_id','credential_type','first_seen_after','last_seen_after','lifecycle_state'))+'<button>Filter</button></form>'
    body+=table(payload['items'],['id','severity','title','repository_id','confidence','observed_by','first_seen_at','last_seen_at','lifecycle_state'])
    body+=''.join(f'<p><a href="/dashboard/assessments/{assessment["id"]}/findings/{r["id"]}">Finding {r["id"]}: {esc(r["title"])}</a></p>' for r in payload['items'])
    body+=paging(f'/dashboard/assessments/{assessment["id"]}/findings?'+urlencode(filters),payload['total'],payload['offset'],payload['limit'])
    return page(assessment['name']+' — Findings',body,assessment=assessment)


def graph(assessment,payload,filters=None):
    filters={k:v for k,v in (filters or {}).items() if v is not None}
    root=f'/dashboard/assessments/{assessment["id"]}/relationships'
    body='<form method="get">'+''.join(input_field(k,k,filters.get(k,'')) for k in ('entity_type','entity_id','relation_type','confidence'))+'<button>Filter relationships</button></form>'
    body+=table(payload['edges'],['from','relation_type','to','confidence','source','provenance','first_seen','last_seen'])
    body+='<h2>Explore connected assets</h2>'
    for node in payload['nodes']:
        body+='<p><a href="'+esc(root+'?'+urlencode({'entity_type':node['entity_type'],'entity_id':node['entity_id']}))+'">'+esc(node['label'])+'</a> ('+esc(node['entity_type'])+')</p>'
        if node['entity_type']=='repository':body+=f'<a href="/dashboard/assessments/{assessment["id"]}/findings?repository_id={node["entity_id"]}">Repository findings</a>'
    body+=paging(root+'?'+urlencode(filters),payload['total'],payload['offset'],payload['limit'])
    body+=form(f'/dashboard/assessments/{assessment["id"]}/launch/ai','<input type="hidden" name="purpose" value="correlations">','Explain relationships with Local AI')
    return page(assessment['name']+' — Relationships',body,assessment=assessment)


def connections(payload,tenant):
    body='<p>Tokens are provisioned as environment variables in API and worker processes. Enter only the variable name; tokens are never stored here.</p>'
    body+=table(payload['items'],['id','name','connection_type','web_base_url','api_base_url','enabled','last_test_status','metadata_json'])
    auth=current_auth.get()
    if auth and auth.allows_role('admin'):
        body+=form('/dashboard/settings/github',input_field('tenant','Tenant',tenant)+input_field('name','Name')+
            '<select name="connection_type"><option>github</option><option>ghes</option></select>'+input_field('web_base_url','Web URL','https://github.com')+
            input_field('api_base_url','API URL','https://api.github.com')+input_field('credential_env','Credential environment reference')+
            '<label><input type="checkbox" name="allow_private" value="true">Permit explicitly selected private/internal scope</label>','Add GitHub connection')
        for row in payload['items']:
            body+='<h2>'+esc(row['name'])+'</h2>'
            controls=input_field('tenant','Tenant',tenant,type='hidden')+input_field('name','Name',row['name'])+input_field('credential_env','Credential reference',row['credential_env'])
            for key,label in (('enabled','Enabled'),('allow_private','Permit explicitly selected private/internal scope')):
                controls+=f'<label><input type="checkbox" name="{key}" value="true" '+('checked' if row[key] else '')+'>'+label+'</label>'
            body+=form(f'/dashboard/settings/github/{row["id"]}/edit',controls,'Save connection')
            body+=form(f'/dashboard/settings/github/{row["id"]}/test',input_field('tenant','Tenant',tenant,type='hidden'),'Test connection')
        body+='<p>To change an endpoint, add a connection and import targets for that host. Existing targets retain their original connection.</p>'
    body+='<p><a href="/dashboard/settings/local-ai">Local AI settings</a></p>'
    return page('GitHub Connections',body)


def local_ai(config,tenant):
    body='<p>Optional local AI. Suggestions never change deterministic evidence or finding decisions.</p>'
    body+='<p>Status: '+esc(config.get('status','Not tested'))+' · Protected data: disabled · Source code: disabled</p>'
    controls=input_field('tenant','Tenant',tenant)+input_field('base_url','Ollama endpoint',config['base_url'])
    controls+=input_field('model','Installed model',config['model']).replace('<input ', '<input list="installed-models" ',1)
    controls+='<datalist id="installed-models">'+''.join('<option value="'+esc(row['name'])+'">' for row in config.get('models',[]))+'</datalist>'
    controls+='<label><input type="checkbox" name="enabled" value="true" '+('checked' if config['enabled'] else '')+'>Enable Local AI</label>'
    controls+='<button name="action" value="test">Save and test connection</button>'
    body+=form('/dashboard/settings/local-ai',controls,'Save settings')
    body+=table(config.get('models',[]),['name','size'])
    return page('Local AI settings',body)


def advice(assessment,payload):
    body='<p>AI Suggested: advisory output only. Deterministic confidence remains authoritative. Results describe bounded input at generation time.</p>'
    for purpose in ('summary','correlations','triage','repository','finding'):
        body+=form(f'/dashboard/assessments/{assessment["id"]}/launch/ai',f'<input type="hidden" name="purpose" value="{purpose}">'+(input_field('entity_id','Repository ID' if purpose=='repository' else 'Finding ID') if purpose in ('repository','finding') else ''),'Generate '+purpose+' advice')
    for row in payload['items']:
        body+='<h2>'+esc(row['purpose'])+' — AI Suggested</h2>'
        body+='<p>'+esc(row['provider'])+' / '+esc(row['model'])+' · '+esc(row['created_at'])+' · '+esc(row['policy_version'])+'</p>'
        body+=table([row['output_json']],['classification','confidence','explanation','suggested_tags'])
    return page(assessment['name']+' — Local AI',body,assessment=assessment)


def edit_assessment(assessment):
    controls=input_field('name','Assessment name',assessment['name'])
    controls+='<label>Description<textarea name="description">'+esc(assessment['description'])+'</textarea></label>'
    controls+='<label>Status<select name="status"><option value="">Keep current: '+esc(assessment['status'])+'</option>'+''.join(f'<option value="{state}" '+('selected' if state==assessment['status'] else '')+'>'+state.title()+'</option>' for state in ('draft','ready','paused','completed','archived'))+'</select></label>'
    return '<details><summary>Edit assessment</summary>'+form(f'/dashboard/assessments/{assessment["id"]}/edit',controls)+'</details>'


def scan_review(assessment,preview):
    root=f'/dashboard/assessments/{assessment["id"]}'
    body=f'<p>{preview["repositories"]} repositories · {len(preview["scanners"])} scanners · History '+('enabled' if preview['history_enabled'] else 'disabled')+'</p>'
    body+='<p>Scanners: '+esc(', '.join(preview['scanners']))+'</p>'
    controls=input_field('action','', 'confirmed',type='hidden')
    for key,value in preview['options'].items():
        if value is None:continue
        if key=='refs':value=','.join(value)
        for item in value if isinstance(value,list) else [value]:controls+=input_field(key,'',item,type='hidden')
    body+=form(root+'/launch/scan',controls,'Start scan')
    return page(assessment['name']+' — Review scan',body,assessment=assessment)


def discovery_review(assessment,review):
    from orgscan.web.recon import STYLE,badge
    options=review['options'];hidden=''
    for key,value in options.items():
        if key=='name':key='profile'
        if isinstance(value,bool):value='true' if value else 'false'
        for item in value if isinstance(value,list) else [value]:
            hidden+='<input type="hidden" name="'+esc(key)+'" value="'+esc(str(item))+'">'
    body=STYLE+'<h2>Review active validation</h2><p>Targets: '+str(review['targets'])+' · Previously observed HTTP services: '+str(review['http_endpoints'])+'</p><p>Counts can change as upstream stages finish. Tools run only against scoped, validated inputs.</p>'
    body+='<h3>Active tools</h3>'+''.join(badge(tool,'recon-active') for tool in review['active_tools'])
    body+='<p>Crawling, port discovery and template checks interact with targets. Nuclei uses only configured local templates. Third-party references are not authorized targets.</p>'
    body+=form('/dashboard/assessments/'+str(assessment['id'])+'/launch/discovery',hidden+'<input type="hidden" name="action" value="confirmed">','Start Active Validation')
    return page('Review active validation',body,assessment=assessment)
