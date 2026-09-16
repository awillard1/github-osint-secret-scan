import pytest
from fastapi import HTTPException
from orgscan.auth import resolve_requested_tenants
from orgscan.security_context import AuthContext


def test_public_tenant_compatibility_helper():
    reader = AuthContext('reader', 'reader', ('a', 'b'), True)
    assert resolve_requested_tenants(reader) == ['a', 'b']
    assert resolve_requested_tenants(reader, 'a') == ['a']
    with pytest.raises(HTTPException) as raised:
        resolve_requested_tenants(reader, 'foreign')
    assert raised.value.status_code == 403
    wildcard = AuthContext('admin', 'admin', ('*',), True)
    assert resolve_requested_tenants(wildcard) is None
    assert resolve_requested_tenants(wildcard, 'a') == ['a']
