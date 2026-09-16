"""Presentation limits for summary previews; durable records remain unchanged."""
from orgscan.redaction import redact


def bounded_summary(value):
    # Sanitize before clipping so copied credential knowledge is not lost.
    value = redact(value, preserve_root_keys=True)
    def metadata(item):
        characters, nodes = 8192, 128
        def walk(child, depth=0):
            nonlocal characters, nodes
            nodes -= 1
            if characters <= 0 or nodes < 0 or depth > 6:
                return '<truncated>'
            if isinstance(child, str):
                result = child[:min(2048, characters)]
                characters -= len(result)
                return result if result == child else result + '…'
            if isinstance(child, list):
                return [walk(entry, depth+1) for entry in child[:32]]
            if isinstance(child, dict):
                return {str(key)[:128]: walk(entry, depth+1) for key, entry in list(child.items())[:32]}
            return child
        return walk(item)
    def preview(item):
        if isinstance(item, str):
            return item if len(item) <= 2048 else item[:2048] + '…'
        if isinstance(item, list):
            return [preview(child) for child in item]
        if isinstance(item, dict):
            return {str(key)[:2048]: metadata(child) if key == 'provenance' else preview(child)
                    for key, child in item.items()}
        return item
    result = preview(value)
    result['summary_limits'] = {'collection_rows':200, 'text_characters':2048,
                              'graph_edges':200, 'graph_nodes':400,
                              'provenance_characters':8192, 'aggregate_counts':'all authorized rows'}
    return result
