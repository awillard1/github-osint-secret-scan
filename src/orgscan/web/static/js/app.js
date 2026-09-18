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

// AI advice remains server-rendered. Refresh only the bounded, authorized job and
// advice fragment while a durable operation is active; forms retain native fallback.
const aiPoll = document.querySelector('[data-ai-poll]');
if (aiPoll && window.fetch) {
  const refreshed = document.getElementById('ai-refresh');
  const warning = document.getElementById('ai-refresh-warning');
  const change = document.getElementById('ai-status-change');
  const region = () => document.getElementById('ai-activity');
  const active = () => region()?.dataset.aiActive === 'true';
  let timer;
  let pending = false;
  let failures = 0;
  let actionPending = false;
  let revision = 0;
  const schedule = () => {
    clearTimeout(timer);
    if (active() && !document.hidden && !actionPending) timer = setTimeout(refresh, Math.min(60000, 10000 * 2 ** failures));
  };
  const replace = (markup) => {
    const next = new DOMParser().parseFromString(markup, 'text/html').querySelector('#ai-activity');
    if (!next || !region()) throw new Error('incomplete activity');
    const previous = region().querySelector('.activity-state')?.textContent?.trim();
    const current = next.querySelector('.activity-state')?.textContent?.trim();
    region().replaceWith(next);
    if (current && current !== previous) change.textContent = `AI job status: ${current}.`;
    refreshed.textContent = `Last refreshed at ${new Date().toLocaleTimeString()}.`;
    aiPoll.removeAttribute('data-warning');
    warning.textContent = '';
    failures = 0;
  };
  const refresh = async (force = false) => {
    if (pending || actionPending || document.hidden || (!force && !active())) return;
    pending = true;
    const requestRevision = revision;
    try {
      const response = await fetch(aiPoll.dataset.aiPoll, {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('refresh failed');
      const markup = await response.text();
      if (requestRevision === revision) replace(markup);
    } catch (_) {
      failures = Math.min(failures + 1, 4);
      aiPoll.setAttribute('data-warning', '');
      warning.textContent = 'Live refresh is temporarily unavailable. Saved status remains visible.';
    } finally {
      pending = false;
      schedule();
    }
  };
  document.getElementById('ai-refresh-now')?.addEventListener('click', (event) => {
    event.preventDefault();
    refresh(true);
  });
  document.addEventListener('visibilitychange', () => {
    clearTimeout(timer);
    if (!document.hidden && active()) refresh();
  });
  document.addEventListener('submit', async (event) => {
    const form = event.target.closest('form[data-ai-action]');
    if (!form) return;
    event.preventDefault();
    if (actionPending) return;
    actionPending = true;
    revision += 1;
    clearTimeout(timer);
    const button = form.querySelector('button[type="submit"]');
    if (button) button.disabled = true;
    change.textContent = 'Saving advisory request.';
    try {
      const response = await fetch(form.action, {method: 'POST', body: new FormData(form),
        credentials: 'same-origin', redirect: 'follow'});
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('action failed');
      replace(await response.text());
      change.textContent = 'Advisory request saved. Job status is shown below.';
    } catch (_) {
      change.textContent = 'Advisory request could not be saved.';
      aiPoll.setAttribute('data-warning', '');
      warning.textContent = 'Check the selected record and local AI settings, then try again.';
      if (button && button.isConnected) button.disabled = false;
    } finally {
      actionPending = false;
      schedule();
    }
  });
  schedule();
}
