"""Conservative local HTTP template policy; no automatic template acquisition."""
from pathlib import Path
import yaml
import json


def validated_templates(directory, destination=None):
    if not directory:raise ValueError('Configure an explicit local Nuclei template directory')
    root=Path(directory).resolve()
    if not root.is_dir():raise ValueError('Nuclei template directory is unavailable')
    paths=sorted(root.rglob('*.yaml'))
    if not paths or len(paths)>100:raise ValueError('Select between 1 and 100 approved local HTTP templates')
    snapshots=[]
    for path in paths:
        if path.is_symlink() or root not in path.resolve().parents or path.stat().st_size>65536:
            raise ValueError('Unsafe or oversized Nuclei template')
        try:record=yaml.safe_load(path.read_text())
        except (ValueError,yaml.YAMLError):raise ValueError('Invalid local Nuclei template') from None
        if not isinstance(record,dict) or set(record)-{'id','info','http'} or not isinstance(record.get('http'),list):
            raise ValueError('Only approved local HTTP templates are supported')
        for request in record['http']:
            if not isinstance(request,dict) or set(request)-{'method','path','matchers','matchers-condition','extractors','stop-at-first-match'}:
                raise ValueError('Template uses unsupported execution or redirect behavior')
            if request.get('method','GET') not in ('GET','HEAD'):
                raise ValueError('Template policy permits GET and HEAD only')
            request_paths=request.get('path',[])
            if not request_paths or not isinstance(request_paths,list) or any(not isinstance(p,str) or not p.startswith('{{BaseURL}}/') or '{{' in p[len('{{BaseURL}}'):] for p in request_paths):
                raise ValueError('Template paths must stay on the selected BaseURL')
        encoded=json.dumps(record)
        if len(encoded)>65536:raise ValueError('Expanded template exceeds policy size')
        if destination is not None:
            destination.mkdir(exist_ok=True)
            snapshot=destination/(str(len(snapshots))+'.yaml')
            snapshot.write_text(encoded)
            snapshots.append(snapshot)
        else:snapshots.append(path)
    return snapshots
