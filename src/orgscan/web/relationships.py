"""Presentation mapping for already authorized and sanitized relationship DTOs."""
from orgscan.web.render import render


def page(payload, *, assessment=None, filters=None):
    nodes = {str(node['id']): node for node in payload.get('nodes', [])}
    edges = []
    for edge in payload.get('edges', []):
        source = nodes.get(str(edge['from']), {})
        target = nodes.get(str(edge['to']), {})
        evidence = edge.get('provenance') or {}
        observations = evidence.get('provenance', []) if isinstance(evidence, dict) else evidence
        reason = next((row.get('reason') for row in observations if isinstance(row, dict)
                       and isinstance(row.get('reason'), str)), None)
        edges.append({**edge, 'from_label': source.get('label', edge['from']),
                      'to_label': target.get('label', edge['to']),
                      'from_kind': source.get('entity_type', ''),
                      'to_kind': target.get('entity_type', ''),
                      'reason': reason[:300] if reason else None})
    return render('pages/relationships.html', title='Relationships',
                  active_section='assessments' if assessment else 'relationships', assessment=assessment, payload=payload,
                  nodes=list(nodes.values()), edges=edges, filters=filters or {})
