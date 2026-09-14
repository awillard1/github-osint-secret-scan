"""No plaintext is embedded in initial HTML or persistent browser storage."""
import html
from orgscan.security_context import current_auth, current_csrf, AuthorizationError
from orgscan.services.secret_evidence import SecretEvidenceService


def render_secret_controls(settings, finding_id):
    auth = current_auth.get()
    if not auth or not auth.authenticated:
        return ''
    try:
        payload = SecretEvidenceService(settings).metadata(finding_id, auth)
    except AuthorizationError:
        return ''
    rows = []
    for row in payload['secrets']:
        button = (f'<button type="button" data-reveal="{row["id"]}">Reveal</button>'
                  '<button type="button" data-hide hidden>Hide</button>') if payload['can_reveal'] else ''
        rows.append(f'<div data-secret-row><span>{html.escape(row["secret_type"])}</span> '
                    f'<code data-secret-value>••••••••••••</code> {button}</div>')
    if not rows:
        return ''
    return (f'<section id="protected-secrets" data-finding="{finding_id}" '
            f'data-csrf="{html.escape(current_csrf.get() or "", quote=True)}">'
            '<h2>Protected secret evidence</h2><p>Sensitive: reveal is audited. Values hide after 30 seconds.</p>'+
            ''.join(rows)+'</section>'+SCRIPT)


SCRIPT = r'''<script>
(() => {
 const section = document.getElementById('protected-secrets');
 if (!section) return;
 const rows = Array.from(section.querySelectorAll('[data-secret-row]'));
 rows.forEach(row => {
   const reveal = row.querySelector('[data-reveal]'), hide = row.querySelector('[data-hide]');
   const output = row.querySelector('[data-secret-value]');
   if (!reveal) return;
   let version = 0, timer;
   const clear = () => { version++; clearTimeout(timer); output.textContent = '••••••••••••';
     hide.hidden = true; reveal.disabled = false; };
   hide.onclick = clear;
   document.addEventListener('visibilitychange', () => { if (document.hidden) clear(); });
   window.addEventListener('pagehide', clear);
   reveal.onclick = async () => {
     clear(); const requested = version; reveal.disabled = true; hide.hidden = false;
     try {
       const response = await fetch('/findings/'+section.dataset.finding+'/secrets/'+reveal.dataset.reveal+'/reveal', {
         method:'POST', credentials:'same-origin', cache:'no-store',
         headers:{'X-CSRF-Token':section.dataset.csrf}});
       if (!response.ok) throw new Error('unavailable');
       const payload = await response.json();
       if (requested !== version || document.hidden) return;
       output.textContent = payload.value; payload.value = null;
       timer = setTimeout(clear, 30000);
     } catch (_) { if (requested === version) { clear(); output.textContent = 'Reveal unavailable'; } }
   };
 });
})();
</script>'''
