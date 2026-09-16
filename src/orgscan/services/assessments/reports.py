"""Assessment report packaging over the existing canonical report renderers."""
import csv
import json
from html import escape
from orgscan.reporting import write_export


def write_assessment_export(path,format,payload):
    assessment=payload['assessment']
    if format=='json':
        path.write_text(json.dumps(payload,default=str,ensure_ascii=False),encoding='utf-8')
        return path
    if format=='csv':
        # Heterogeneous scope and canonical evidence are preserved as typed records.
        # JSON cells begin with an object delimiter, avoiding spreadsheet formulas.
        with path.open('w',newline='',encoding='utf-8') as stream:
            writer=csv.writer(stream);writer.writerow(['record_type','record_json'])
            writer.writerow(['assessment',json.dumps({k:v for k,v in assessment.items() if k!='scope'},default=str)])
            for kind,section in assessment['scope'].items():
                writer.writerow([kind+'_summary',json.dumps({k:v for k,v in section.items() if k!='items'})])
                for row in section['items']:writer.writerow([kind,json.dumps(row,default=str)])
            for row in payload['findings']:writer.writerow(['finding',json.dumps(row,default=str)])
        return path
    if format=='pdf':
        from orgscan.reports.pdf import write_pdf_report
        return write_pdf_report(path,payload['summary'],payload['findings'],variant='technical')
    write_export(path,format,payload['summary'],payload['findings'])
    if format=='sarif':
        data=json.loads(path.read_text())
        for run in data['runs']:run.setdefault('properties',{})['assessment']=assessment
        path.write_text(json.dumps(data,default=str),encoding='utf-8')
    elif format=='html':
        sections='<section><h1>Assessment: '+escape(assessment['name'])+'</h1><p>'+escape(assessment['description'])+'</p><p>'+escape(assessment['detail_policy'])+'</p>'
        if assessment.get('ai_summary'):sections+='<h2>AI Suggested executive summary</h2><p>'+escape(assessment['ai_summary']['advice']['explanation'])+'</p>'
        for kind,section in assessment['scope'].items():
            sections+='<h2>'+escape(kind.title())+' ('+str(section['total'])+')</h2>'
            if section['truncated']:sections+='<p>Detail truncated; use paginated assessment views for remaining records.</p>'
            for row in section['items']:sections+='<pre>'+escape(json.dumps(row,default=str,indent=2))+'</pre>'
        text=path.read_text();path.write_text(text.replace('</main>',sections+'</section></main>'),encoding='utf-8')
    return path
