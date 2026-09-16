"""Authoritative recon inventory. Detection never installs or enables execution."""
from dataclasses import asdict, dataclass
from pathlib import Path
import os
import platform
import re
import shutil
import tempfile

from orgscan import processes

PASSIVE = 'Passive'
LOW_IMPACT = 'Low-impact active'
ACTIVE = 'Active'


@dataclass(frozen=True)
class ToolDefinition:
    tool_id: str
    display_name: str
    category: str
    description: str
    homepage: str
    mode: str = PASSIVE
    executables: tuple[str, ...] = ()
    go_package: str | None = None
    version_command: tuple[str, ...] = ('-version',)
    version_pattern: str = r'(?i)(?:version[: ]*|\bv)(\d+\.\d+(?:\.\d+)?(?:[-+][\w.]+)?)'
    supported_platforms: tuple[str, ...] = ('Linux', 'Darwin')
    capabilities: tuple[str, ...] = ('domain',)
    configuration_requirements: tuple[str, ...] = ()
    optional_api_keys: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()
    guidance: str = ''
    adapter: str = 'legacy'
    stage_order: int = 0
    required_flags: tuple[str, ...] = ()

    @property
    def installation_methods(self):
        return ('go',) if self.go_package else ('manual',) if self.executables else ()


def pd(name, display, category, description, mode, package=None, **kwargs):
    return ToolDefinition(name, display, category, description, 'https://github.com/projectdiscovery/'+name,
                          mode, (name,), package or 'github.com/projectdiscovery/'+name+'/cmd/'+name, adapter='recon',
                          stage_order={'SUBDOMAIN_DISCOVERY':0,'DNS':1,'HTTP_PROBING':2,'PORT_DISCOVERY':3,'CRAWLING':3,'TEMPLATE_SCANNING':4}[category],
                          required_flags={
                              'subfinder':('-d','-json','-silent','-duc','-s','-pc'),
                              'dnsx':('-l','-json','-a','-aaaa','-cname','-mx','-ns','-txt','-duc','-r'),
                              'httpx':('-l','-json','-status-code','-title','-tech-detect','-ip','-location','-duc','-r','-ports'),
                              'naabu':('-list','-json','-scan-type','-Pn','-p','-rate','-duc','-r'),
                              'katana':('-list','-jsonl','-d','-cs','-fs','-dr','-omit-raw','-omit-body','-rl','-c','-duc','-r'),
                              'nuclei':('-l','-jsonl','-duc','-ni','-dr','-type','-rl','-c','-omit-raw','-no-color','-t','-r'),
                          }[name], **kwargs)


DEFINITIONS = (
    pd('subfinder','Subfinder','SUBDOMAIN_DISCOVERY','Passive subdomain enumeration',PASSIVE,
       package='github.com/projectdiscovery/subfinder/v2/cmd/subfinder', optional_api_keys=('subfinder_provider_config',)),
    pd('httpx','HTTPX','HTTP_PROBING','HTTP status, titles and technology observations',ACTIVE, capabilities=('http_service',)),
    pd('dnsx','DNSX','DNS','Resolve and enrich DNS records',LOW_IMPACT, capabilities=('domain','ip_address')),
    pd('naabu','Naabu','PORT_DISCOVERY','Bounded TCP connect port discovery',ACTIVE,
       package='github.com/projectdiscovery/naabu/v2/cmd/naabu', capabilities=('network_service',)),
    pd('katana','Katana','CRAWLING','Crawl explicitly scoped HTTP targets',ACTIVE, capabilities=('endpoint',), dependencies=('httpx',)),
    pd('nuclei','Nuclei','TEMPLATE_SCANNING','Explicit local template checks',ACTIVE,
       package='github.com/projectdiscovery/nuclei/v3/cmd/nuclei', capabilities=('finding',),
       configuration_requirements=('nuclei_templates_path',), dependencies=('httpx',)),
    ToolDefinition('amass','Amass','SUBDOMAIN_DISCOVERY','Complementary passive domain intelligence',
       'https://github.com/owasp-amass/amass', adapter='recon',executables=('amass',),
       guidance='Install an official Amass release with enum -passive support. Version 3 is supported; newer CLI contracts require validation.'),
    ToolDefinition('gau','gau','ARCHIVE_DISCOVERY','Historical URLs from passive indexes','https://github.com/lc/gau',
       adapter='recon',executables=('gau',), go_package='github.com/lc/gau/v2/cmd/gau',version_command=('--version',),capabilities=('endpoint',)),
    ToolDefinition('whois','WHOIS','OSINT','Complementary registration metadata; not ownership proof',
       'https://github.com/rfc1036/whois',executables=('whois',),version_command=('--version',),
       guidance='Install whois with your operating system package manager. orgscan does not request sudo.'),
    ToolDefinition('rdap','RDAP','BUILTIN_PROVIDER','Structured registration metadata','https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml',adapter='recon'),
    ToolDefinition('crtsh','crt.sh','BUILTIN_PROVIDER','Certificate transparency names and SANs','https://crt.sh'),
    ToolDefinition('wayback','Wayback','ARCHIVE_DISCOVERY','Historical URLs from the CDX API','https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server',adapter='recon',capabilities=('endpoint',)),
    ToolDefinition('local-metadata','Repository metadata','BUILTIN_PROVIDER','Stored repository domain references','https://github.com'),
    ToolDefinition('dns','DNS','DNS','Built-in DNS resolution','https://www.dnspython.org',LOW_IMPACT),
    ToolDefinition('securitytxt','security.txt','HTTP_PROBING','Fetch target security.txt files','https://securitytxt.org',ACTIVE),
    ToolDefinition('github-search','GitHub Search','GITHUB','Connection-scoped GitHub intelligence','https://docs.github.com/en/rest/search'),
    ToolDefinition('hibp','Have I Been Pwned','OSINT','Breach metadata','https://haveibeenpwned.com/API/v3',configuration_requirements=('hibp_api_key',)),
    ToolDefinition('dehashed','DeHashed','OSINT','Exposure intelligence','https://www.dehashed.com',configuration_requirements=('dehashed_email','dehashed_api_key')),
    ToolDefinition('intelligencex','Intelligence X','OSINT','Indexed exposure intelligence','https://intelx.io',configuration_requirements=('intelligencex_api_key',)),
    ToolDefinition('projectdiscovery','ProjectDiscovery legacy pipeline','HTTP_PROBING','Subfinder followed by active HTTP probing','https://projectdiscovery.io',ACTIVE,dependencies=('subfinder','httpx')),
    ToolDefinition('all','Legacy aggregate','OSINT','Legacy combined providers','https://github.com',ACTIVE,dependencies=('crtsh','whois','projectdiscovery')),
    ToolDefinition('all-enriched','Legacy enriched aggregate','OSINT','Legacy combined providers with enrichment','https://github.com',ACTIVE,dependencies=('all','securitytxt','dns')),
)


def controlled_environment(home):
    # Credentials, proxy injection and user tool configuration are not inherited.
    return {'PATH': os.defpath, 'HOME': str(home), 'XDG_CONFIG_HOME': str(home),
            'LANG': 'C.UTF-8', 'NO_COLOR': '1', 'DISABLE_AUTO_UPDATE': 'true'}


class ReconToolRegistry:
    def __init__(self, definitions=DEFINITIONS):
        self.definitions = {}
        for definition in definitions:
            if definition.tool_id in self.definitions:
                raise ValueError('Duplicate recon tool ID')
            self.definitions[definition.tool_id] = definition

    def get(self, tool_id):
        if tool_id not in self.definitions:
            raise ValueError('Unknown recon tool')
        return self.definitions[tool_id]

    def bin_dir(self, settings):
        return (settings.recon_tools_dir or settings.data_dir / 'tools').expanduser().resolve() / 'bin'

    def binary(self, tool_id, settings):
        tool = self.get(tool_id)
        if not tool.executables:
            return None
        configured = getattr(settings, tool_id+'_binary', tool.executables[0])
        if configured != tool.executables[0]:
            found=shutil.which(configured)
            return str(Path(found).resolve()) if found else None
        managed = self.bin_dir(settings) / tool.executables[0]
        if managed.is_file() and not managed.is_symlink() and os.access(managed, os.X_OK):
            return str(managed)
        found=shutil.which(configured)
        return str(Path(found).resolve()) if found else None

    def readiness(self, tool_id, settings, *, binary=None):
        tool = self.get(tool_id)
        missing = [key for key in tool.configuration_requirements if not getattr(settings,key,None)]
        if tool_id == 'nuclei' and settings.nuclei_templates_path:
            path = Path(settings.nuclei_templates_path)
            if not path.is_dir() or path.is_symlink():
                missing.append('nuclei_templates_path')
        result = {'tool_id':tool_id,'ready':False,'status':'missing','installed':False,'version':None,
                  'missing':missing,'installable':bool(tool.go_package),'binary_path':None}
        if platform.system() not in tool.supported_platforms:
            return {**result,'status':'unsupported_platform'}
        if not tool.executables:
            unavailable=[name for name in tool.dependencies if not self.readiness(name,settings)['ready']]
            return {**result,'ready':not missing and not unavailable,'installed':True,
                    'status':'configuration_required' if missing or unavailable else 'ready',
                    'missing':missing+unavailable,'version':'API' if tool_id in ('crtsh','wayback','github-search') else 'built-in'}
        binary = binary or self.binary(tool_id, settings)
        if not binary:
            return result
        result.update(installed=True,binary_path=binary,status='unverified')
        try:
            with tempfile.TemporaryDirectory(prefix='orgscan-tool-check-') as directory:
                output = processes.run([binary,*tool.version_command],timeout=5,max_output_bytes=16384,
                                       cwd=directory,env=controlled_environment(directory))
            value = output.stdout+'\n'+output.stderr
            match = re.search(tool.version_pattern,value)
            identity = re.search(r'(?i)\b'+re.escape(tool_id)+r'\b',value)
            # ProjectDiscovery banners often print only "Current Version".
            if tool.go_package and 'projectdiscovery' in tool.go_package:
                identity = identity or ('projectdiscovery.io' in value.lower())
            if tool_id=='amass' and match and match[1].startswith('3.') and not identity:
                with tempfile.TemporaryDirectory(prefix='orgscan-amass-check-') as directory:
                    help_output=processes.run([binary,'enum','-h'],timeout=5,max_output_bytes=16384,
                        cwd=directory,env=controlled_environment(directory))
                help_text=(help_output.stdout+'\n'+help_output.stderr).lower()
                identity=help_output.returncode==0 and 'amass' in help_text and '-passive' in help_text
            if output.returncode != 0 or not match or not identity:
                return result
            result['version'] = match[1]
            if tool.required_flags:
                with tempfile.TemporaryDirectory(prefix='orgscan-contract-check-') as directory:
                    help_output=processes.run([binary,'-h'],timeout=5,max_output_bytes=131072,
                        cwd=directory,env=controlled_environment(directory))
                advertised=set(re.findall(r'(?<!\S)(--?[a-zA-Z][a-zA-Z0-9-]*)',help_output.stdout+'\n'+help_output.stderr))
                if help_output.returncode or not set(tool.required_flags)<=advertised:
                    return {**result,'status':'unsupported_contract'}
            if tool_id=='amass' and not match[1].startswith('3.'):
                return {**result,'status':'unsupported_version'}
            result.update(ready=not missing,status='configuration_required' if missing else 'ready')
        except (OSError,processes.TimeoutExpired,processes.OutputLimitExceeded):
            pass
        return result

    def inventory(self,settings):
        return [{**asdict(tool),'installation_methods':tool.installation_methods,
                 'update_mechanism':'verified Go installation' if tool.go_package else 'manual' if tool.executables else 'application update',
                 **self.readiness(tool.tool_id,settings)} for tool in self.definitions.values()]


_REGISTRY = ReconToolRegistry()


def get_registry():
    return _REGISTRY
