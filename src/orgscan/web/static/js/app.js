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
