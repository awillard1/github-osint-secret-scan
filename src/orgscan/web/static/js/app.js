// The server owns authorization and lifecycle decisions. This only refreshes the view.
document.addEventListener('submit', async (event) => {
  const form = event.target.closest('form[data-enhance="decision"]');
  // Protected reveal controls initialize on a full page load and may hold
  // short-lived plaintext. Keep their normal navigation and cleanup behavior.
  if (!form || !window.fetch || document.getElementById('protected-secrets')) return;

  event.preventDefault();
  const button = form.querySelector('button[type="submit"]');
  if (button) button.disabled = true;

  try {
    const response = await fetch(form.action, {
      method: 'POST',
      body: new FormData(form),
      credentials: 'same-origin',
      redirect: 'follow',
    });
    if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) {
      throw new Error('Decision could not be saved');
    }
    const next = new DOMParser().parseFromString(await response.text(), 'text/html');
    const content = next.querySelector('#content');
    if (!content) throw new Error('Decision response was incomplete');
    document.querySelector('#content').replaceWith(content);
    const heading = content.querySelector('h1');
    if (heading) {
      heading.tabIndex = -1;
      heading.focus();
    }
    history.replaceState(null, '', response.url);
  } catch (_) {
    let notice = form.querySelector('[role="alert"]');
    if (!notice) {
      notice = document.createElement('p');
      notice.setAttribute('role', 'alert');
      form.append(notice);
    }
    notice.textContent = 'Decision could not be saved. Check the form and try again.';
    if (button) button.disabled = false;
  }
});

// The server renders status and decides when an operation is terminal. The browser
// only replaces that fragment and manages request cadence and page visibility.
const discovery = document.querySelector('[data-discovery-poll]');
document.querySelectorAll('[data-select-providers]').forEach(button => {
  button.addEventListener('click', () => {
    const form = button.closest('form');
    if (!form) return;
    form.querySelectorAll('input[name="providers"]').forEach(choice => {
      choice.checked = button.dataset.selectProviders === 'all'
        ? choice.dataset.ready === 'true'
        : button.dataset.selectProviders === 'passive'
          ? choice.dataset.ready === 'true' && choice.dataset.mode === 'passive'
          : false;
    });
  });
});
if (discovery && window.fetch) {
  const refresh = document.getElementById('discovery-refresh');
  const warning = document.getElementById('discovery-refresh-warning');
  const statusChange = document.getElementById('discovery-status-change');
  let failures = 0;
  let timer;
  let pending = false;
  const active = () => discovery.querySelector('[data-terminal="false"]') !== null;
  const schedule = () => {
    clearTimeout(timer);
    if (active() && !document.hidden) timer = setTimeout(poll, Math.min(60000, 5000 * 2 ** failures));
  };
  const poll = async () => {
    if (pending || document.hidden || !active()) return;
    pending = true;
    try {
      const response = await fetch(discovery.dataset.discoveryPoll, {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('refresh failed');
      const next = new DOMParser().parseFromString(await response.text(), 'text/html').querySelector('.discovery-activity');
      if (!next) throw new Error('incomplete refresh');
      const previousState = discovery.querySelector('.activity-lead .activity-state')?.textContent?.trim();
      const nextState = next.querySelector('.activity-lead .activity-state')?.textContent?.trim();
      discovery.replaceChildren(next);
      if (nextState && nextState !== previousState && statusChange) statusChange.textContent = `Discovery status: ${nextState}.`;
      failures = 0;
      refresh.removeAttribute('data-warning');
      warning.textContent = '';
      refresh.firstChild.textContent = `Last refreshed at ${new Date().toLocaleTimeString()}. `;
    } catch (_) {
      failures = Math.min(failures + 1, 4);
      refresh.setAttribute('data-warning', '');
      warning.textContent = 'Live refresh is temporarily unavailable. The saved status remains visible.';
    } finally {
      pending = false;
      schedule();
    }
  };
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (!document.hidden && active()) poll();
  });
  schedule();
}
