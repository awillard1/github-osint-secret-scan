"""Per-operation Git credentials, never command arguments or persisted URLs."""
from contextlib import contextmanager
import base64
import os
from orgscan.mirroring import _GIT_ENV


@contextmanager
def connection_git_environment(connection,settings):
    env={'GIT_TERMINAL_PROMPT':'0','GIT_CONFIG_COUNT':'1',
         'GIT_CONFIG_KEY_0':'http.followRedirects','GIT_CONFIG_VALUE_0':'false'}
    if connection is not None:
        if not connection.enabled:raise ValueError('GitHub connection is disabled')
        from orgscan.services.assessments.github import connection_token
        token=connection_token(settings,connection)
        if token:
            env.update(GIT_CONFIG_COUNT='2',GIT_CONFIG_KEY_1='http.'+connection.web_base_url+'/.extraHeader',
                GIT_CONFIG_VALUE_1='Authorization: Basic '+base64.b64encode(('x-access-token:'+token).encode()).decode())
    marker=_GIT_ENV.set(env)
    try:yield
    finally:_GIT_ENV.reset(marker)
