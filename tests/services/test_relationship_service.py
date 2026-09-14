from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.discovery import GitHubDiscoveryClient
from orgscan.expansion import GitHubExpansionEngine
from orgscan.repositories import Storage
from orgscan.reporting import relationship_graph, render_graph_html
from orgscan.services.relationship_service import public_domain


def test_expansion_explains_relationships_and_corrects_legacy_forks(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'graph.db'}"
    init_db(url)
    client = GitHubDiscoveryClient(Settings())
    payloads = {
        '/repos/example/app': {'full_name':'example/app', 'owner':{'login':'example','type':'Organization'}, 'homepage':'https://example.org'},
        '/repos/example/app/contributors?per_page=20': [{'login':'alice','type':'User'}],
        '/repos/example/app/forks?per_page=20': [{'full_name':'alice/fork', 'owner':{'login':'alice','type':'User'}}],
        '/repos/example/app/commits?per_page=20': [
            {'sha':'a'*40, 'author':{'login':'alice'}, 'commit':{'author':{'email':'alice@example.org'}}},
            {'sha':'b'*40, 'author':None, 'commit':{'author':{'email':'123@users.noreply.github.com'}}},
        ],
    }
    monkeypatch.setattr(client, '_request_json', lambda path: payloads[path])
    with create_session_factory(url)() as session:
        storage = Storage(session)
        parent = storage.create_repository('example/app', metadata_json={'repository_state':{'checkpoint':'keep'}})
        fork = storage.create_repository('alice/fork')
        storage.create_relationship('repository',str(parent.id),'repository',str(fork.id),'fork_of',source='github-api')
        engine = GitHubExpansionEngine(client, storage)
        result = engine.expand_repository('example/app')
        assert result.accounts == ['alice']
        assert result.repositories == ['alice/fork']
        assert parent.metadata_json['repository_state'] == {'checkpoint':'keep'}
        graph = relationship_graph(storage)
        edges = graph['edges']
        assert {edge['relation_type'] for edge in edges} == {'owns','fork_of','contributes_to','mentions','used_email_domain'}
        fork_edge = next(edge for edge in edges if edge['relation_type'] == 'fork_of')
        assert fork_edge['from'] == f'repository:{fork.id}'
        assert fork_edge['to'] == f'repository:{parent.id}'
        assert fork_edge['confidence'] == 'verified'
        email_edge = next(edge for edge in edges if edge['relation_type'] == 'used_email_domain')
        assert email_edge['confidence'] == 'heuristic'
        for edge in edges:
            assert edge['source'] == 'github-api'
            assert edge['provenance']['first_observed_at']
            assert all(item['reason'] and item['api_url'].startswith('https://api.github.com/') for item in edge['provenance']['provenance'])
        assert 'alice@example.org' not in repr(edges)
        assert len(storage.list_domains()) == 1
        assert engine.expand_repository('example/app').relationships == 0
        assert len(relationship_graph(storage)['edges']) == len(edges)
        page = render_graph_html(graph)
        assert 'Why associated' in page
        assert 'GitHub fork listing' in page
        email_edge['provenance']['provenance'][0]['reason'] = '<script>alert(1)</script>'
        assert '<script>alert(1)</script>' not in render_graph_html(graph)


def test_organization_does_not_claim_mismatched_owner(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'organization.db'}"
    init_db(url)
    client = GitHubDiscoveryClient(Settings())
    monkeypatch.setattr(client, '_request_json', lambda path: [
        {'full_name':'example/app','owner':{'login':'example','type':'Organization'}},
        {'full_name':'someone/other','owner':{'login':'someone','type':'User'}},
    ])
    with create_session_factory(url)() as session:
        storage = Storage(session)
        GitHubExpansionEngine(client,storage).expand_organization('example')
        assert storage.get_repository_by_full_name('example/app').organization_id is not None
        assert storage.get_repository_by_full_name('someone/other').organization_id is None


def test_domain_signals_reject_local_invalid_and_github_noreply():
    for name in ('localhost','127.0.0.1','users.noreply.github.com','invalid..example','bad/path.com'):
        assert public_domain(name) is None
    assert public_domain('Example.ORG.') == 'example.org'
