import pytest

from orgscan.auth import create_db_session_token
from orgscan.config import Settings
from orgscan.db import create_session_factory, init_db
from orgscan.repositories import Storage
from orgscan.services.auth_service import AuthService


def test_session_scopes_and_roles_cannot_exceed_membership(tmp_path):
    url = f"sqlite:///{tmp_path / 'roles.db'}"
    init_db(url)
    with create_session_factory(url)() as session:
        storage = Storage(session)
        user = storage.create_user('alice')
        with pytest.raises(ValueError,match='memberships'):
            create_db_session_token(storage,username='alice')
        with pytest.raises(ValueError,match='Invalid tenant or role'):
            storage.grant_tenant_membership(user.id,'a','superuser')
        storage.grant_tenant_membership(user.id,'a','reader')
        storage.grant_tenant_membership(user.id,'b','admin')
        with pytest.raises(ValueError,match='exceeds'):
            create_db_session_token(storage,username='alice',tenants=['a','b'],role='admin')
        with pytest.raises(ValueError,match='memberships'):
            create_db_session_token(storage,username='alice',tenants=['*'])
        _, combined = create_db_session_token(storage,username='alice')
        _, restricted = create_db_session_token(storage,username='alice',tenants=['b'])
        session.commit()
    auth = AuthService(Settings(database_url=url,api_tokens_json=''))
    assert auth.resolve(combined).role == 'reader'
    assert auth.resolve(restricted).role == 'admin'
    assert auth.resolve(restricted).tenants == ('b',)
