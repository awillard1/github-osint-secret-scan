"""Bounded relationship and endpoint projections; callers provide source context."""
from sqlalchemy import String, cast, select
from orgscan import models as m
from orgscan.storage.visibility import visibility_ids


def graph_projection(storage, *, limit=200, tenant_keys=None):
    if not 0 <= limit <= 1000:
        raise ValueError('Invalid graph limit')
    session = storage.session
    conditions = {} if tenant_keys is None else {model: model.id.in_(ids)
        for model, ids in visibility_ids(tenant_keys).items()}
    relationships = list(session.scalars(select(m.Relationship).where(conditions.get(m.Relationship, True))
        .order_by(m.Relationship.id.desc()).limit(limit)))
    endpoint_ids = {}
    for relation in relationships:
        for side in ('from', 'to'):
            kind, identity = getattr(relation, side+'_entity_type'), getattr(relation, side+'_entity_id')
            endpoint_ids.setdefault(kind, set()).add(identity)
    labels = {}
    for kind, model, label in (('organization', m.Organization, m.Organization.name),
                               ('repository', m.Repository, m.Repository.full_name),
                               ('account', m.Account, m.Account.username), ('domain', m.Domain, m.Domain.name)):
        if endpoint_ids.get(kind):
            endpoints = session.execute(select(model.id, label).where(conditions.get(model, True),
                cast(model.id, String).in_(endpoint_ids[kind])))
            labels.update({(kind, str(identity)): value for identity, value in endpoints})
    graph = {'nodes': [], 'edges': [], 'summary': {}}
    nodes, relations = {}, {}
    for relation in relationships:
        endpoints = []
        for side in ('from', 'to'):
            kind, identity = getattr(relation, side+'_entity_type'), getattr(relation, side+'_entity_id')
            key = f'{kind}:{identity}'
            node = nodes.setdefault(key, dict(id=key, entity_type=kind, entity_id=identity, label=labels.get((kind, identity), key), degree=0))
            node['degree'] += 1
            endpoints.append(key)
        graph['edges'].append(dict(id=str(relation.id), **{'from': endpoints[0], 'to': endpoints[1]},
            relation_type=relation.relation_type, confidence=relation.confidence, source=relation.source or '', provenance=relation.metadata_json))
        relations[relation.relation_type] = relations.get(relation.relation_type, 0) + 1
    graph['nodes'] = list(nodes.values())
    graph['summary'] = dict(node_count=len(nodes), edge_count=len(graph['edges']), relation_breakdown=relations,
                           entity_breakdown={kind: sum(n['entity_type'] == kind for n in nodes.values()) for kind in sorted({n['entity_type'] for n in nodes.values()})})
    return graph
