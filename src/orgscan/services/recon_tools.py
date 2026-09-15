"""Shared tool management service for CLI and authenticated presentation."""
from orgscan.recon.registry import get_registry,PASSIVE
from orgscan.recon.installer import ToolInstaller,require_tool_admin


class ReconToolsService:
    def __init__(self,settings):self.settings=settings;self.registry=get_registry()

    def inventory(self):
        rows=self.registry.inventory(self.settings)
        # Never expose configured filesystem paths or configuration values.
        for row in rows:row.pop('binary_path',None)
        return rows

    def test(self,tool_id):
        row=self.registry.readiness(tool_id,self.settings)
        row.pop('binary_path',None)
        return row

    def install(self,tool_id):return ToolInstaller(self.settings).install(tool_id)

    def install_group(self,group):
        require_tool_admin()
        if group not in ('passive','active'):raise ValueError('Invalid tool group')
        results=[]
        for tool in self.registry.definitions.values():
            if not tool.go_package or (tool.mode==PASSIVE)!=(group=='passive'):continue
            if self.registry.readiness(tool.tool_id,self.settings)['installed']:continue
            try:results.append(self.install(tool.tool_id))
            except ValueError:results.append({'tool_id':tool.tool_id,'status':'failed'})
        return results


    def install_missing(self,tool_ids):
        require_tool_admin()
        if not isinstance(tool_ids,list) or len(tool_ids)>len(self.registry.definitions):
            raise ValueError('Invalid selected tool inventory')
        definitions=[self.registry.get(tool_id) for tool_id in dict.fromkeys(tool_ids)]
        results=[]
        for tool in definitions:
            state=self.registry.readiness(tool.tool_id,self.settings)
            if state['installed']:continue
            if not tool.go_package:
                results.append({'tool_id':tool.tool_id,'status':'manual_install_required'});continue
            try:results.append(self.install(tool.tool_id))
            except ValueError:results.append({'tool_id':tool.tool_id,'status':'failed'})
        root=self.registry.bin_dir(self.settings).parent
        root.mkdir(parents=True,exist_ok=True,mode=0o700)
        ToolInstaller._record(root,{'tool_id':'selected-tools','status':'completed' if all(r['status']=='completed' for r in results) else 'needs_attention','results':results})
        return results

    def background_operation(self,tool_id,auth,*,group=False):
        from orgscan.security_context import current_auth
        marker=current_auth.set(auth)
        try:
            if isinstance(tool_id,list):self.install_missing(tool_id)
            elif group:self.install_group(tool_id)
            else:self.install(tool_id)
        except ValueError:
            root=self.registry.bin_dir(self.settings).parent
            root.mkdir(parents=True,exist_ok=True,mode=0o700)
            ToolInstaller._record(root,{'tool_id':tool_id,'status':'failed','error':'Installation unavailable; check the configured Go toolchain and upstream prerequisites'})
            # Installer persists bounded safe diagnostics; background errors must
            # not escape into server logs with subprocess context.
            pass
        finally:current_auth.reset(marker)
