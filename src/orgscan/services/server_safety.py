"""Explicit network exposure policy for the server adapter."""
import ipaddress
import warnings


def validate_bind(host, *, authenticated, unsafe_override=False):
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host.lower() == 'localhost'
    if loopback or authenticated:
        return
    if not unsafe_override:
        raise ValueError('Refusing unauthenticated non-loopback binding. Configure authentication or explicitly use --unsafe-allow-unauthenticated-network for development.')
    warnings.warn('UNSAFE DEVELOPMENT: unauthenticated network access grants unrestricted administrator privileges.', RuntimeWarning, stacklevel=2)
