const returnTo = new URLSearchParams(window.location.search).get('returnTo');
const authSwitchLink = document.querySelector('.signup-footer a');
const allowedReturnPaths = new Set([
  '/index.html',
  '/education.html',
  '/technology.html',
  '/arts.html',
  '/sports.html',
  '/profile.html',
  '/account.html',
]);

function getPostAuthPath() {
  if (!returnTo) {
    return '/profile.html';
  }
  try {
    const destination = new URL(returnTo, window.location.origin);
    if (destination.origin === window.location.origin && allowedReturnPaths.has(destination.pathname)) {
      return `${destination.pathname}${destination.search}${destination.hash}`;
    }
  } catch {
    return '/profile.html';
  }
  return '/profile.html';
}

if (returnTo && authSwitchLink) {
  const switchUrl = new URL(authSwitchLink.getAttribute('href'), window.location.href);
  switchUrl.searchParams.set('returnTo', returnTo);
  authSwitchLink.href = `${switchUrl.pathname}${switchUrl.search}`;
}

document.querySelectorAll('[data-auth-form]').forEach((form) => {
  const message = form.querySelector('[data-auth-message]');
  const submitButton = form.querySelector('button[type="submit"]');

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    message.textContent = '';
    submitButton.disabled = true;

    const formData = new FormData(form);
    const action = form.dataset.authForm;
    const payload = {
      identifier: formData.get('identifier'),
      password: formData.get('password'),
    };

    if (action === 'register') {
      if (payload.password !== formData.get('confirmPassword')) {
        message.textContent = 'Passwords do not match.';
        submitButton.disabled = false;
        return;
      }
      payload.firstName = formData.get('firstName');
      payload.lastName = formData.get('lastName');
    }

    try {
      const response = await fetch(`/api/auth/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || 'Unable to complete your request.');
      }
      window.location.assign(getPostAuthPath());
    } catch (error) {
      message.textContent = error instanceof TypeError
        ? 'Unable to reach the authentication service. Please try again later.'
        : error.message;
      submitButton.disabled = false;
    }
  });
});