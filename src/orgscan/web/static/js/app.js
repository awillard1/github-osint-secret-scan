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

document.addEventListener('DOMContentLoaded', () => {
  if (!window.fetch) return;
  let root = document.querySelector('[data-assessment-activity]');
  if (!root) return;
  let timer = 0;
  let failures = 0;

  const setRefresh = (state, message) => {
    root = document.querySelector('[data-assessment-activity]');
    if (!root) return;
    const stateNode = root.querySelector('[data-refresh-state]');
    const timeNode = root.querySelector('[data-refresh-time]');
    if (stateNode) stateNode.textContent = state;
    if (timeNode) timeNode.textContent = message;
  };

  const schedule = (delay) => {
    clearTimeout(timer);
    root = document.querySelector('[data-assessment-activity]');
    if (!root || root.dataset.terminal === 'true') {
      setRefresh('Auto refresh stopped', 'A terminal state is shown. Refresh after any retry or relaunch.');
      return;
    }
    timer = window.setTimeout(refresh, delay);
  };

  const refresh = async () => {
    root = document.querySelector('[data-assessment-activity]');
    if (!root) return;
    if (document.hidden) {
      setRefresh('Auto refresh paused', 'Refresh pauses while this tab is hidden and resumes when you return.');
      schedule(15000);
      return;
    }
    try {
      const response = await fetch(root.dataset.pollUrl, {
        credentials: 'same-origin',
        headers: {'X-Requested-With': 'fetch'},
      });
      if (!response.ok) throw new Error('refresh_failed');
      const next = new DOMParser().parseFromString(await response.text(), 'text/html');
      const replacement = next.querySelector('[data-assessment-activity]');
      if (!replacement) throw new Error('refresh_incomplete');
      root.replaceWith(replacement);
      root = replacement;
      failures = 0;
      setRefresh('Auto refresh active', `Last refreshed at ${new Date().toLocaleTimeString()}. If updates pause briefly, the last saved durable state remains visible.`);
      schedule(root.dataset.terminal === 'true' ? 0 : 5000);
    } catch (_) {
      failures += 1;
      setRefresh('Refresh delayed', 'Live refresh is temporarily unavailable. The latest saved server state is still shown.');
      schedule(Math.min(60000, 5000 * (2 ** failures)));
    }
  };

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    refresh();
  });

  schedule(5000);
});
