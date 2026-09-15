"""Complete derived DTOs cross this boundary before source knowledge is lost."""
from functools import wraps
from orgscan.storage.credential_context import CredentialContext, build_projection_context


def safe_projection(storage, projected_value, *, family, tenant_keys=None, source_context=None):
    context = source_context if source_context is not None else build_projection_context(
        storage, family=family, tenant_keys=tenant_keys)
    if not isinstance(context, CredentialContext):
        raise TypeError('Complete credential context is required')
    # Only the wrapper key is application-controlled: a projection may itself be
    # a mapping whose keys are legacy scanner/category/severity values.
    return context.sanitize({'projection': projected_value})['projection']


def derived_projection(family):
    """Storage/report compatibility entry points retain context through projection."""
    def decorate(function):
        @wraps(function)
        def wrapped(storage, *args, **kwargs):
            context = build_projection_context(storage, family=family,
                tenant_keys=kwargs.get('tenant_keys'))
            return safe_projection(storage, function(storage, *args, **kwargs),
                                   family=family, source_context=context)
        return wrapped
    return decorate
