"""Recon management and canonical result views; no tool dispatch in HTML."""
from orgscan.web.assessments import esc,page,form,paging

STYLE='''<style>
.recon-hero{display:flex;justify-content:space-between;gap:24px;align-items:start;margin:24px 0}.recon-kicker{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#147a96;font-weight:700}.recon-muted{color:#52647b;max-width:760px}.recon-toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin:20px 0}.recon-toolbar form{margin:0}.recon-panel{border:1px solid #dbe3ef;border-radius:12px;overflow:auto;margin:20px 0}.recon-table{width:100%;border-collapse:collapse}.recon-table td,.recon-table th{padding:16px;text-align:left;border-bottom:1px solid #dbe3ef;vertical-align:top}.recon-table th{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:#52647b}.recon-tool{font-weight:700;font-size:16px}.recon-purpose{font-size:13px;color:#52647b;margin-top:5px;max-width:340px}.recon-badge{display:inline-block;border-radius:20px;padding:4px 10px;font-size:12px;font-weight:600;background:#e7eef8;color:#254b75;margin:2px;white-space:nowrap}.recon-ready{background:#123f36;color:#7de4b6}.recon-missing{background:#493522;color:#ffd08a}.recon-active{background:#482c42;color:#f5acd9}.recon-passive{background:#183b50;color:#8dd9ef}.recon-actions{display:flex;gap:8px;flex-wrap:wrap}.recon-actions form{margin:0}.recon-actions button{padding:6px 12px}button{border:1px solid #cbd5e1;border-radius:7px;background:#fff;padding:9px 14px;color:#0f172a;cursor:pointer}button:hover{background:#eff6ff}input,select,textarea{padding:8px;border:1px solid #cbd5e1;border-radius:6px}input[type=checkbox]{accent-color:#2563eb}nav{margin-bottom:16px;line-height:2}a:focus-visible,button:focus-visible{outline:3px solid #38bdf8;outline-offset:3px}.recon-summary{display:flex;gap:16px;flex-wrap:wrap}.recon-stat{padding:18px 24px;border:1px solid #dbe3ef;border-radius:10px;min-width:140px}.recon-stat strong{display:block;font-size:28px}.recon-tabs{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}.recon-tabs a{padding:8px 14px;border:1px solid #dbe3ef;border-radius:8px}.recon-notice{padding:16px;border-left:3px solid #147a96;background:#e9f5fa;margin:16px 0}details summary{cursor:pointer} .recon-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px}.recon-choice{border:1px solid #dbe3ef;border-radius:8px;padding:12px}.recon-choice label{display:block}
</style>'''


def badge(value,kind=''):
    return '<span class="recon-badge '+esc(kind)+'">'+esc(value)+'</span>'


def tools(rows,installation=None,can_install=False):
    rows=[r for r in rows if r['tool_id'] not in ('all','all-enriched','projectdiscovery')]
    ready=sum(r['ready'] for r in rows)
    body=STYLE+'<div class="recon-hero"><div><div class="recon-kicker">Settings / Recon tools</div><h2>Your reconnaissance toolchain</h2><p class="recon-muted">Manage the providers that power organization discovery. Readiness comes from local detection and configuration checks. Installing a tool does not enable it in an assessment.</p></div></div>'
    body+='<div class="recon-tabs"><a href="/dashboard/settings/github">GitHub connections</a><a href="/dashboard/settings/recon-tools" aria-current="page">Recon Tools</a><a href="/dashboard/settings/local-ai">Local AI</a></div>'
    body+='<div class="recon-summary">'+''.join('<div class="recon-stat"><strong>'+str(n)+'</strong>'+label+'</div>' for n,label in ((ready,'Ready'),(len(rows)-ready,'Need attention'),(sum(bool(r['go_package']) for r in rows),'Managed installers')))+'</div>'
    body+='<div class="recon-toolbar">'
    if can_install:
        body+=form('/dashboard/settings/recon-tools/install-passive','','Install Recommended Passive Tools')
        body+=form('/dashboard/settings/recon-tools/install-active','','Install Active Recon Tools')
    body+='<a href="/dashboard/settings/recon-tools">Refresh Status</a></div>'
    if not can_install:body+='<p class="recon-muted">A platform administrator manages shared executable installations. Tenant operators can review readiness and select assessment tools.</p>'
    if installation and installation.get('status')=='installing':body+='<meta http-equiv="refresh" content="5"><p role="status">Installing… This page refreshes while installation runs.</p>'
    if installation:body+='<div class="recon-notice" role="status">Last installation: '+esc(installation.get('tool_id',''))+' · '+esc(installation.get('status',''))+' '+esc(installation.get('version',''))+' '+esc(installation.get('error',''))+'</div>'
    body+='<div class="recon-panel"><table class="recon-table"><thead><tr>'+''.join('<th>'+v+'</th>' for v in ('Tool / Purpose','Mode','Installed','Status','Version','Configuration','Actions'))+'</tr></thead><tbody>'
    for row in rows:
        identity=row['tool_id'];root='/dashboard/settings/recon-tools/'+identity
        configuration='<details><summary>Configure</summary><p>'+esc(row['guidance'] or 'Set administrator environment configuration, then refresh readiness.')+'</p>'
        for key in (*row['configuration_requirements'],*row['optional_api_keys']):configuration+='<p><code>ORGSCAN_'+esc(key.upper())+'</code></p>'
        if row['executables']:configuration+='<p><code>ORGSCAN_'+esc(identity.upper())+'_BINARY</code></p>'
        configuration+='</details>'
        actions='<a href="'+esc(row['homepage'])+'" target="_blank" rel="noopener noreferrer">Docs</a>'
        if can_install and row['installable']:actions+=form(root+'/install','', 'Update' if row['installed'] else 'Install')
        actions+=form(root+'/test','','Test')
        status=row['status'].replace('_',' ').title()
        body+='<tr><td><div class="recon-tool">'+esc(row['display_name'])+'</div><div class="recon-purpose">'+esc(row['description'])+'</div></td><td>'+badge(row['mode'],'recon-passive' if row['mode']=='Passive' else 'recon-active')+'</td><td>'+('Yes' if row['installed'] else 'No')+'</td><td>'+badge(status,'recon-ready' if row['ready'] else 'recon-missing')+'</td><td>'+esc(row['version'] or '—')+'</td><td>'+configuration+'</td><td><div class="recon-actions">'+actions+'</div></td></tr>'
    body+='</tbody></table></div><p class="recon-muted">Go installation uses official module paths and a private staging directory. Configure ORGSCAN_RECON_GO_BINARY to use a local Go toolchain. No sudo or startup installation.</p>'
    return page('Recon Tools',body)


def results(assessment,payload,tab='overview',offset=0):
    root='/dashboard/assessments/'+str(assessment['id'])
    body=STYLE+'<div class="recon-kicker">Assessment / Discovery results</div><p class="recon-muted">Canonical observations from selected providers. Sources show where an asset was observed; they do not establish ownership.</p>'
    body+='<div class="recon-tabs">'+''.join('<a href="'+root+'/recon-results?tab='+key+'"'+(' aria-current="page"' if key==tab else '')+'>'+label+'</a>' for key,label in (('overview','Overview'),('domains','Domains'),('hosts','Hosts'),('services','Services'),('web','Web')))+''.join('<a href="'+root+'/'+key+'">'+label+'</a>' for key,label in (('repositories','Repositories'),('accounts','Accounts'),('relationships','Relationships')))+'</div>'
    if tab=='overview':
        body+='<div class="recon-summary">'+''.join('<div class="recon-stat"><strong>'+str(value)+'</strong>'+esc(key.replace('_',' ').title())+'</div>' for key,value in payload['counts'].items())+'</div>'
        body+='<p><a href="'+root+'/discovery">Configure providers and launch discovery →</a></p>'
    elif not payload['items']:body+='<div class="recon-notice">No observations yet. Select a discovery profile and run it against your saved targets.</div>'
    else:
        columns={'domains':['Domain','Resolved?','HTTP?','Sources','First seen','Last seen'],'hosts':['Host / IP','DNS','Ports / HTTP','Sources','First seen','Last seen'],'services':['Service','Status / Port','Technology','Sources','First seen','Last seen'],'web':['URL','Status','Title / Technology','Sources','First seen','Last seen']}[tab]
        body+='<div class="recon-panel"><table class="recon-table"><thead><tr>'+''.join('<th>'+c+'</th>' for c in columns)+'</tr></thead><tbody>'
        for row in payload['items']:
            entity=row['entity'];meta=entity.get('metadata_json') or {};link=row.get('metadata_json') or {}
            sources=link.get('sources',[row.get('source')])
            if tab=='domains':
                meta={'status':'Yes' if link.get('dns') else 'Not observed','title':str(link.get('http_status') or 'Not observed')}
            elif tab=='hosts':
                meta={'status':meta.get('hostname') or 'Not observed','title':meta.get('port') or 'See Services'}
            body+='<tr><td>'+esc(entity.get('name'))+'</td><td>'+esc(meta.get('status') or meta.get('port') or link.get('dns') or '—')+'</td><td>'+esc(meta.get('title',''))+' '+esc(', '.join(meta.get('tech',[])))+'</td><td>'+''.join(badge(s) for s in sources)+'</td><td>'+esc(link.get('first_seen'))+'</td><td>'+esc(link.get('last_seen'))+'</td></tr>'
        body+='</tbody></table></div>'+paging(root+'/recon-results?tab='+tab,payload['total'],offset)
    return page('Discovery Results',body,assessment=assessment)
