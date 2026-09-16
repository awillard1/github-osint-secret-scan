"""Bounded provider adapters. Targets and arguments are generated from scope."""
import ipaddress
import json
from pathlib import Path
import re
import tempfile
from urllib.parse import urlencode,urlsplit
from orgscan import processes
from orgscan.recon.registry import controlled_environment,get_registry
from orgscan.recon.observations import Observation,domain,scoped_host,url

TOOLS = tuple(tool.tool_id for tool in get_registry().definitions.values() if tool.adapter=='recon')


class ReconError(ValueError):
    def __init__(self,message,code='provider_failed'):
        self.code=code
        super().__init__(message)


def json_lines(output):
    rows=[]
    for line in output.splitlines():
        if not line.strip():continue
        try:row=json.loads(line)
        except ValueError:raise ReconError('Provider returned malformed JSON','invalid_output') from None
        if not isinstance(row,dict):raise ReconError('Provider returned invalid records','invalid_output')
        rows.append(row)
    return rows


class Adapter:
    def __init__(self,settings):self.settings=settings;self.registry=get_registry()

    def run(self,tool_id,root,inputs,*,timeout=None):
        if not domain(root) or domain(root)!=root:raise ReconError('Invalid domain scope','invalid_scope')
        if not inputs:return []
        for value in inputs:
            if not isinstance(value,str) or any(c in value for c in ('\n','\r','\x00')):
                raise ReconError('Invalid recon input','invalid_scope')
            host=urlsplit(value).hostname if value.startswith(('https://','http://')) else value
            if not scoped_host(host,root) or (tool_id in ('katana','nuclei') and url(value)!=value):
                raise ReconError('Recon input is outside authorized scope','invalid_scope')
        maximum=self.settings.recon_max_urls if tool_id in ('katana','nuclei') else self.settings.recon_max_domains
        if tool_id in ('dnsx','httpx','naabu'):maximum=min(maximum,self.settings.recon_max_hosts)
        if len(inputs)>maximum:raise ReconError('LIMIT REACHED: input targets','limit_reached')
        if tool_id in ('rdap','wayback'):
            from orgscan.providers import provider_budget
            with provider_budget(min(timeout or self.settings.recon_tool_timeout_seconds,self.settings.recon_tool_timeout_seconds)):
                return self.api(tool_id,root)
        binary=self.registry.binary(tool_id,self.settings)
        if not binary:raise ReconError('Selected tool is missing','missing_tool')
        with tempfile.TemporaryDirectory(prefix='orgscan-recon-') as temporary:
            work=Path(temporary);targets=work/'targets.txt'
            targets.write_text('\n'.join(inputs)+'\n',encoding='utf-8')
            command=self.command(tool_id,binary,root,targets,work)
            environment=controlled_environment(work)
            if tool_id=='nuclei':environment['DISABLE_NUCLEI_TEMPLATES_PUBLIC_DOWNLOAD']='true'
            try:
                result=processes.run(command,cwd=work,env=environment,
                    timeout=min(timeout or self.settings.recon_tool_timeout_seconds,self.settings.recon_tool_timeout_seconds),
                    max_output_bytes=self.settings.recon_max_output_bytes)
            except processes.OutputLimitExceeded:raise ReconError('LIMIT REACHED: tool output','limit_reached') from None
            except processes.TimeoutExpired:raise ReconError('Tool execution timed out','timeout') from None
            except OSError:raise ReconError('Tool could not be started','process_failed') from None
            if result.returncode:raise ReconError('Tool execution failed; verify installation and configuration')
            return self.parse(tool_id,root,result.stdout)

    def command(self,tool,binary,root,targets,work):
        commands={
            'subfinder':['-d',root,'-json','-silent','-duc'],
            'dnsx':['-l',str(targets),'-json','-silent','-a','-aaaa','-cname','-mx','-ns','-txt','-duc'],
            'httpx':['-l',str(targets),'-json','-silent','-status-code','-title','-tech-detect','-ip','-location','-duc'],
            'naabu':['-list',str(targets),'-json','-silent','-scan-type','CONNECT','-Pn','-p','80,443,8080,8443','-rate','50','-duc'],
            'katana':['-list',str(targets),'-jsonl','-silent','-d','2','-cs',r'^https?://(?:[a-z0-9-]+\.)*'+re.escape(root)+r'(?::[0-9]+)?(?:/|$)','-fs','fqdn','-dr','-omit-raw','-omit-body','-rl','10','-c','2','-duc'],
            'amass':['enum','-passive','-d',root,'-nocolor','-dir',str(work/'amass')],
            'gau':['--subs','--providers','wayback,commoncrawl',root],
        }
        if tool=='nuclei':
            from orgscan.recon.templates import validated_templates
            templates=validated_templates(self.settings.nuclei_templates_path,work/'templates')
            args=['-l',str(targets),'-jsonl','-silent','-duc','-ni','-dr','-type','http','-rl','10','-c','2','-omit-raw','-no-color']
            for template in templates:args.extend(['-t',str(template)])
            if self.settings.recon_resolvers:
                resolvers=work/'resolvers.txt'
                resolvers.write_text('\n'.join(self.settings.recon_resolvers)+'\n')
                args.extend(['-r',str(resolvers)])
            return [binary,*args]
        if tool not in commands:raise ReconError('Unsupported recon adapter')
        args=commands[tool]
        if tool=='subfinder' and self.settings.subfinder_provider_config:
            args+=['-pc',str(Path(self.settings.subfinder_provider_config).resolve())]
        if tool=='subfinder' and self.settings.subfinder_sources:
            args+=['-s',','.join(self.settings.subfinder_sources)]
        if tool in ('dnsx','httpx','katana','naabu') and self.settings.recon_resolvers:
            args+=['-r',','.join(self.settings.recon_resolvers)]
        if tool=='httpx' and self.settings.recon_http_ports:
            args+=['-ports',','.join('http:'+str(port) for port in self.settings.recon_http_ports)]
        return [binary,*args]

    def parse(self,tool,root,output):
        if tool in ('amass','gau'):
            rows=[{'host':line.strip()} if tool=='amass' else {'url':line.strip()} for line in output.splitlines() if line.strip()]
        else:rows=json_lines(output)
        from orgscan.storage.credential_context import CredentialContext
        rows=CredentialContext(rows).sanitize({'rows':rows})['rows']
        observations=[]
        for row in rows:
            if tool in ('subfinder','amass','dnsx'):
                host=domain(row.get('host') or row.get('name') or '')
                if not scoped_host(host,root):continue
                attributes={}
                if tool=='dnsx':
                    attributes={'dns':{key:row[key] for key in ('a','aaaa','cname','mx','ns','txt','rcode') if key in row}}
                    if row.get('status_code'):attributes['dns']['rcode']=row['status_code']
                observations.append(Observation('domain',host,tool,attributes))
                for value in [*row.get('a',[]),*row.get('aaaa',[])]:
                    try:value=str(ipaddress.ip_address(value))
                    except ValueError:continue
                    observations.append(Observation('ip_address',value,tool,{'hostname':host}))
            elif tool in ('httpx','katana','gau'):
                address=url(row.get('url') or (row.get('request') or {}).get('endpoint') or '')
                if not address or not scoped_host(urlsplit(address).hostname,root):continue
                attributes={}
                if tool=='httpx':
                    status=row.get('status_code') or row.get('status-code')
                    if type(status) is int and 100<=status<=599:attributes['status']=status
                    attributes.update({key:row[key] for key in ('title','tech','location','host','host_ip','a','aaaa','webserver','content_type') if key in row})
                observations.append(Observation('http_service' if tool=='httpx' else 'endpoint',address,tool,attributes))
            elif tool=='naabu':
                host=domain(row.get('host') or '')
                if not scoped_host(host,root):continue
                try:address=str(ipaddress.ip_address(row.get('ip','')));port=int(row.get('port',0))
                except (ValueError,TypeError):continue
                if port not in (80,443,8080,8443):continue
                observations.append(Observation('ip_address',address,tool,{'hostname':host}))
                observations.append(Observation('network_service',f'{address}:{port}/tcp',tool,{'ip':address,'port':port,'protocol':'tcp','hostname':host}))
            elif tool=='nuclei':
                address=url(row.get('matched-at') or row.get('host') or '')
                if not address or not scoped_host(urlsplit(address).hostname,root):continue
                info=row.get('info') or {}
                observations.append(Observation('finding',address,tool,{'template_id':row.get('template-id'),
                    'title':info.get('name'),'severity':info.get('severity'),'description':info.get('description')}))
        return observations

    def api(self,tool,root):
        from orgscan.providers import _request_json
        if tool=='wayback':
            endpoint='https://web.archive.org/cdx/search/cdx?'+urlencode({'url':'*.'+root+'/*','output':'json','fl':'original',
                'collapse':'urlkey','limit':self.settings.recon_max_urls+1})
            rows=_request_json(endpoint,settings=self.settings,scope='wayback',expected=list)
            if len(rows)>self.settings.recon_max_urls:raise ReconError('LIMIT REACHED: archive URLs','limit_reached')
            return [Observation('endpoint',address,'wayback') for row in rows if isinstance(row,list) and row
                    and (address:=url(row[0])) and scoped_host(urlsplit(address).hostname,root)]
        # IANA bootstrap chooses the authoritative registry; all requests use HTTPS.
        bootstrap=_request_json('https://data.iana.org/rdap/dns.json',settings=self.settings,scope='rdap-bootstrap',expected=dict)
        bases=[base for suffixes,urls in bootstrap.get('services',[]) if root.rsplit('.',1)[-1] in suffixes for base in urls if base.startswith('https://')]
        if not bases:raise ReconError('No authoritative RDAP service is available')
        record=_request_json(bases[0].rstrip('/')+'/domain/'+root,settings=self.settings,scope='rdap',expected=dict)
        from orgscan.storage.credential_context import CredentialContext
        record=CredentialContext(record).sanitize(record)
        registrars=[];organizations=[]
        for entity in record.get('entities',[]):
            if not isinstance(entity,dict):continue
            cards=entity.get('vcardArray') or []
            values=cards[1] if len(cards)>1 and isinstance(cards[1],list) else []
            names=[item[3] for item in values if isinstance(item,list) and len(item)>3 and item[0] in ('fn','org') and isinstance(item[3],str)]
            if 'registrar' in entity.get('roles',[]):registrars.extend(names)
            elif 'registrant' in entity.get('roles',[]):organizations.extend(names)
        registration={'registrars':registrars,'organizations':organizations,'ownership_proof':False,
            'nameservers':[item.get('ldhName') for item in record.get('nameservers',[]) if isinstance(item,dict)],
            'dates':{event.get('eventAction'):event.get('eventDate') for event in record.get('events',[]) if isinstance(event,dict) and event.get('eventAction')},
            'status':record.get('status',[]),'handle':record.get('handle')}
        return [Observation('domain',root,'rdap',{'registration':registration})]
