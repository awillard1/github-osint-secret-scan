"""Thin assessment HTML adapters over sanitized service projections."""
import html
from urllib.parse import urlencode  # Compatibility for route redirects.

from markupsafe import Markup

from orgscan.web.render import render


def esc(value):
    return html.escape(str(value if value is not None else ''),quote=True)


def page(title,body,*,assessment=None):
    """Compatibility wrapper for callers still supplying escaped static markup."""
    return render('pages/legacy_content.html',title=title,active_section='assessments',
                  heading=title,assessment=assessment,body=Markup(body))


def index(payload,tenant,offset):
    return render('pages/assessment_home.html',title='Assessments',active_section='assessments',
                  payload=payload,tenant=tenant,offset=offset)


def new(tenant):
    return render('pages/assessment_new.html',title='New assessment',active_section='assessments',tenant=tenant)


def targets(assessment,payload,offset,result=None,*,connections=None):
    github_connections=[row for row in (connections or {}).get('items',[])
                        if row['web_base_url']=='https://github.com']
    github_connected=any(row['enabled'] for row in github_connections)
    return render('pages/assessment_targets.html',title=assessment['name']+' — Targets',
                  active_section='assessments',assessment=assessment,payload=payload,offset=offset,
                  result=result,github_connected=github_connected,
                  github_connection_exists=bool(github_connections))


def discovery(assessment,jobs,providers,profiles,saved=()):
    return render('pages/assessment_discovery.html',title=assessment['name']+' — Discovery',
                  active_section='assessments',assessment=assessment,activity=jobs,
                  providers=[row for row in providers if row['name'] not in ('all','all-enriched','github-search','projectdiscovery')],
                  profiles=profiles,saved=saved)


def discovery_fragment(activity):
    return render('components/discovery_activity.html',activity=activity)


def overview(assessment,activity):
    return render('pages/assessment_overview.html',title=assessment['name'],active_section='assessments',
                  assessment=assessment,activity=activity)


def assets(assessment,payload,kind,offset,filters=None):
    selected={key:value for key,value in (filters or {}).items() if value is not None and value!=''}
    return render('pages/assessment_assets.html',title=assessment['name']+' — '+kind.title(),
                  active_section='assessments',assessment=assessment,payload=payload,kind=kind,
                  offset=offset,filters=selected,filter_query=urlencode({key:str(value).lower() if isinstance(value,bool) else value for key,value in selected.items()}))


def scans(assessment,jobs,inventory,profiles,*,db_execution=False):
    return render('pages/assessment_scans.html',title=assessment['name']+' — Scans',active_section='assessments',
                  assessment=assessment,jobs=jobs,inventory=inventory,
                  profiles=[name for name in profiles if name not in ('osint-only','domain-only')],
                  db_execution=db_execution)


def findings(assessment,payload,filters=None):
    selected={key:value for key,value in (filters or {}).items() if value is not None and value!=''}
    return render('pages/assessment_findings.html',title=assessment['name']+' — Findings',
                  active_section='assessments',assessment=assessment,payload=payload,
                  filters=selected,filter_query=urlencode(selected))


def graph(assessment,payload,filters=None):
    from orgscan.web.relationships import page as relationship_page
    return relationship_page(payload,assessment=assessment,filters=filters)


def connections(payload,tenant):
    return render('pages/github_connections.html',title='GitHub connections',active_section='assessments',
                  payload=payload,tenant=tenant)


def local_ai(config,tenant):
    return render('pages/local_ai_settings.html',title='Local AI settings',active_section='assessments',
                  config=config,tenant=tenant)


def advice(assessment,payload):
    return render('pages/assessment_ai.html',title=assessment['name']+' — Local AI',
                  active_section='assessments',assessment=assessment,payload=payload)


def reports(assessment):
    return render('pages/assessment_reports.html',title=assessment['name']+' — Reports',
                  active_section='assessments',assessment=assessment,
                  formats=('json','csv','html','pdf','sarif'))


def scan_review(assessment,preview):
    return render('pages/scan_review.html',title=assessment['name']+' — Review scan',
                  active_section='assessments',assessment=assessment,preview=preview)


def discovery_review(assessment,review):
    return render('pages/discovery_review.html',title='Review discovery launch',
                  active_section='assessments',assessment=assessment,review=review)
