"""Connection-scoped GitHub transport. No redirects or credential-bearing URLs."""
import json
import os
from urllib.error import HTTPError
from urllib.request import Request,build_opener,HTTPRedirectHandler
from orgscan.discovery import GitHubDiscoveryClient,DiscoveryError
from orgscan.http_limits import read_response,response_deadline
from orgscan.rate_limit import wait_for_rate_limit


def connection_token(settings,connection):
    reference=connection.credential_env
    if not reference:return None
    try:
        grants=json.loads(settings.github_connection_credentials_json)
        if (reference not in grants.get(connection.tenant_key,[])
            or any(reference in values for key,values in grants.items() if key!=connection.tenant_key)):
            raise ValueError
    except (TypeError,AttributeError,ValueError):
        raise ValueError('Connection credential reference is not provisioned for this tenant') from None
    token=os.environ.get(reference)
    if not token:raise ValueError('GitHub connection credential is not provisioned in this process')
    return token


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):
        return None


class ConnectionClient(GitHubDiscoveryClient):
    def __init__(self,settings,connection):
        super().__init__(settings)
        if not connection.enabled:raise ValueError('GitHub connection is disabled')
        self.base_url=connection.api_base_url
        self.web_url=connection.web_base_url
        self.scope=f'github-connection:{connection.tenant_key}:{connection.id}'
        self.token=connection_token(settings,connection)
        self.opener=build_opener(NoRedirect())

    def _request_json(self,path):
        from orgscan.cancellation import CancellationRequested, check_cancelled
        check_cancelled()
        if not path.startswith('/') or path.startswith('//') or any(c in path for c in ('\r','\n')):
            raise ValueError('Invalid GitHub endpoint')
        wait_for_rate_limit(self.settings,self.scope)
        headers={'Accept':'application/vnd.github+json','User-Agent':'orgscan'}
        if self.token:headers['Authorization']='Bearer '+self.token
        try:
            with self.opener.open(Request(self.base_url+path,headers=headers),timeout=self.timeout) as response:
                return json.loads(read_response(response,settings=self.settings,deadline=response_deadline(self.timeout)))
        except CancellationRequested:
            raise
        except (HTTPError,OSError) as exc:
            from orgscan.services.job_policy import ClassifiedJobError,classify_failure
            raise ClassifiedJobError(classify_failure(exc)) from None
        except (ValueError,TypeError):
            raise DiscoveryError('GitHub connection response failed size or decoding checks') from None

    def pages(self,path,*,max_pages):
        separator='&' if '?' in path else '?'
        for page in range(1,max_pages+1):
            data=self._request_json(f'{path}{separator}per_page=100&page={page}')
            if not isinstance(data,list):raise DiscoveryError('Expected GitHub list response')
            if len(data)>100:raise DiscoveryError('GitHub page exceeds requested page size')
            yield from (item for item in data if isinstance(item,dict))
            if len(data)<100:return
        # The run is explicitly partial; do not advertise a bounded traversal as exhaustive.
        raise DiscoveryError('Discovery page budget reached; narrow targets or increase the configured page budget')
