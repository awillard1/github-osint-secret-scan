"""Paginated executive and technical reports without raw source material."""
from html import escape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from orgscan.reports.redaction import redact


def write_pdf_report(output_path, summary, findings, *, variant='executive'):
    summary, findings = redact(summary), redact(findings)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    styles = getSampleStyleSheet()
    story = []
    def paragraph(value, style='BodyText'):
        story.append(Paragraph(escape(str(value)).replace('\n','<br/>'), styles[style]))
        story.append(Spacer(1,6))
    paragraph(f'orgscan {variant} report', 'Title')
    paragraph('Scope: stored authorized observations; absence from a report does not prove remediation.')
    paragraph(f'Included findings: {len(findings)}. Summary covers all authorized findings.')
    assessment=summary.get('assessment')
    if assessment:
        import json
        paragraph('Assessment: '+assessment['name'],'Heading1')
        paragraph(assessment.get('description',''))
        paragraph(assessment.get('detail_policy',''))
        if assessment.get('ai_summary'):
            paragraph('AI Suggested executive summary','Heading2')
            paragraph(assessment['ai_summary']['advice']['explanation'])
        for kind,section in assessment.get('scope',{}).items():
            paragraph(f'{kind.title()}: {section["total"]}','Heading2')
            if section.get('truncated'):paragraph('Detail truncated; use paginated assessment views for remaining records.')
            for row in section['items']:
                # Split long records into bounded paragraphs for reliable pagination.
                text=json.dumps(row,default=str,ensure_ascii=False)
                for offset in range(0,len(text),1500):paragraph(text[offset:offset+1500])
    paragraph('Asset and observation counts', 'Heading1')
    paragraph(', '.join(f'{key}={value}' for key,value in sorted(summary.get('counts',{}).items())))
    if variant == 'executive':
        paragraph('Organization comparison', 'Heading1')
        for row in summary.get('organization_comparison',[]):
            paragraph(f'{row["organization"]}: findings={row["findings"]}; critical/high={row["critical_high"]}; open={row["open_findings"]}; average risk={row["average_risk_score"]}')
    paragraph('Severity and lifecycle', 'Heading1')
    for label, key in (('Severity','severity_breakdown'),('Lifecycle','lifecycle_breakdown')):
        paragraph(f'{label}: '+', '.join(f'{name}={count}' for name,count in sorted(summary.get(key,{}).items())))
    if variant == 'executive':
        paragraph('Prioritized findings', 'Heading1')
        for row in sorted(findings,key=lambda item: (-(item.get('risk_score') or 0), item['id']))[:10]:
            paragraph(f'#{row["id"]}: {row["title"]} — {row["severity"]} / {row["confidence"]}; {row.get("lifecycle_state")}; risk {row.get("risk_score",0)}')
            for item in row.get('evidence', []):
                if item.get('path'):
                    paragraph(f"Location: {item['path']}:{item.get('line_start') or ''}")
        paragraph('Recommended actions', 'Heading1')
        for row in summary.get('remediation_suggestions',[]):
            paragraph(f'{row["category"]}: {row["suggestion"]}')
        paragraph('Executive detail is limited to the ten highest-risk included findings; use the technical report for all included issues.')
    else:
        paragraph('Technical findings and scanner evidence', 'Heading1')
        for row in findings:
            paragraph(f'#{row["id"]}: {row["title"]}', 'Heading2')
            paragraph(f'{row["severity"]} / {row["confidence"]}; lifecycle {row.get("lifecycle_state")}; scanner {row["source_tool"]}')
            paragraph(row['description'])
            paragraph(f'Fingerprint: {row["fingerprint"]}')
            paragraph('; '.join(f'{key}: {row.get(key) or "none"}' for key in ('first_seen_at','last_seen_at','remediated_at','regressed_at')))
            if row.get('remediation_hint'):
                paragraph('Remediation: '+row['remediation_hint'])
            for item in row.get('evidence',[]):
                paragraph('; '.join(f'{key}: {item.get(key) or "unavailable"}' for key in ('scanner','path','line_start','commit_sha','ref_name','source_url','query_used','observed_at')))
    if not findings:
        paragraph('No findings in the selected scope.')
    def footer(canvas, doc):
        canvas.setFont('Helvetica',8)
        canvas.drawString(40,25,f'orgscan — page {doc.page}')
    SimpleDocTemplate(str(output_path),pagesize=letter,title=f'orgscan {variant} report',author='orgscan').build(story,onFirstPage=footer,onLaterPages=footer)
    return output_path
