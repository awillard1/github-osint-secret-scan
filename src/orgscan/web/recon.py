"""Server-rendered recon views over sanitized service projections."""
from orgscan.web.render import render


def tools(rows,installation=None,can_install=False):
    rows=[row for row in rows if row['tool_id'] not in ('all','all-enriched','projectdiscovery')]
    return render('pages/recon_tools.html',title='Recon Tools',active_section='assessments',
                  rows=rows,installation=installation,can_install=can_install,
                  ready=sum(bool(row['ready']) for row in rows))


def results(assessment,payload,tab='overview',offset=0,*,probe=None,httpx_ready=None,probe_scope=None,db_execution=False):
    readiness=next((row for row in (httpx_ready or []) if row['name']=='httpx'),None)
    return render('pages/recon_results.html',title='Discovery Results',active_section='assessments',
                  assessment=assessment,payload=payload,tab=tab,offset=offset,
                  probe=probe,httpx_ready=bool(readiness and readiness['status']=='ok'),
                  probe_scope=probe_scope,
                  db_execution=db_execution)
