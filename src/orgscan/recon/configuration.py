"""Platform-owned local template configuration shared by web, workers and doctor."""
import json
import os
from pathlib import Path
import tempfile


def configuration_file(settings):
    return (settings.recon_tools_dir or settings.data_dir / 'tools') / 'templates.json'


def template_locations(settings):
    path = configuration_file(settings)
    if path.is_symlink():
        raise ValueError('Unsafe template configuration')
    if path.exists():
        if path.stat().st_size > 16384:
            raise ValueError('Unsafe template configuration')
        try:
            locations = json.loads(path.read_text())
        except (ValueError, OSError):
            raise ValueError('Invalid template configuration') from None
    else:
        locations = [settings.nuclei_templates_path] if settings.nuclei_templates_path else []
    if not isinstance(locations, list) or len(locations) > 20 or any(
        not isinstance(p, str) or not p or len(p) > 2048 for p in locations
    ):
        raise ValueError('Invalid template locations')
    return locations


def approved_templates(settings, destination=None):
    from orgscan.recon.templates import validated_templates
    locations = template_locations(settings)
    if not locations:
        raise ValueError('Configure explicit local Nuclei template directories')
    paths = []
    for location in locations:
        paths.extend(validated_templates(location))
        if len(paths) > 100:
            raise ValueError('Select at most 100 approved local HTTP templates')
    if destination is None:
        return paths
    snapshots = []
    for index, location in enumerate(locations):
        destination.mkdir(exist_ok=True)
        snapshots.extend(validated_templates(location, destination / str(index)))
    return snapshots


def save_template_locations(settings, locations):
    from orgscan.recon.installer import require_tool_admin, installation_lock
    from orgscan.recon.templates import validated_templates
    require_tool_admin()
    if not isinstance(locations, list) or len(locations) > 20:
        raise ValueError('Select at most 20 local template directories')
    normalized = []
    count = 0
    for location in locations:
        if not isinstance(location, str) or len(location) > 2048 or not Path(location).is_absolute():
            raise ValueError('Template locations must be absolute local directory paths')
        path = Path(location)
        if any(p.is_symlink() for p in (path, *path.parents)):
            raise ValueError('Template locations must not contain symbolic links')
        name = str(path.resolve())
        if name in normalized:
            continue
        count += len(validated_templates(name))
        if count > 100:
            raise ValueError('Select at most 100 approved local HTTP templates')
        normalized.append(name)
    encoded = json.dumps(normalized)
    if len(encoded.encode('utf-8')) > 16384:
        raise ValueError('Template configuration exceeds the storage limit')
    target = configuration_file(settings)
    with installation_lock(target.parent):
        descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix='.templates-')
        try:
            with os.fdopen(descriptor, 'w') as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return {'saved': True, 'locations': len(normalized), 'templates': count}
