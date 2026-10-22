const requestForm = document.querySelector('#recovery-request-form');
const verifyForm = document.querySelector('#recovery-verify-form');
const recoveryComplete = document.querySelector('#recovery-complete');
const requestMessage = document.querySelector('[data-recovery-message]');
const verifyMessage = document.querySelector('[data-recovery-verify-message]');

function showRecoveryMessage(element, text, state = 'error') {
  element.textContent = text;
  element.dataset.state = state;
}

async function postRecoveryRequest(path, payload) {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(result.error || 'Unable to complete password recovery. Please try again.');
  }
  return result;
}

requestForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submitButton = requestForm.querySelector('button[type="submit"]');
  const identifier = new FormData(requestForm).get('identifier').trim();
  submitButton.disabled = true;
  showRecoveryMessage(requestMessage, '');

  try {
    const result = await postRecoveryRequest('/api/auth/password-reset/request', { identifier });
    requestForm.hidden = true;
    verifyForm.elements.namedItem('identifier').value = identifier;
    verifyForm.hidden = false;
    showRecoveryMessage(verifyMessage, result.message, 'success');
    verifyForm.querySelector('[name="code"]').focus();
  } catch (error) {
    showRecoveryMessage(requestMessage, error instanceof TypeError
      ? 'Unable to reach the password recovery service. Please try again later.'
      : error.message);
    submitButton.disabled = false;
  }
});

verifyForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const submitButton = verifyForm.querySelector('button[type="submit"]');
  const formData = new FormData(verifyForm);
  const newPassword = formData.get('newPassword');
  if (newPassword !== formData.get('confirmPassword')) {
    showRecoveryMessage(verifyMessage, 'The new passwords do not match.');
    return;
  }

  submitButton.disabled = true;
  showRecoveryMessage(verifyMessage, '');
  try {
    const result = await postRecoveryRequest('/api/auth/password-reset/verify', {
      identifier: formData.get('identifier'),
      code: formData.get('code').trim(),
      newPassword,
    });
    verifyForm.hidden = true;
    recoveryComplete.hidden = false;
    showRecoveryMessage(verifyMessage, result.message, 'success');
  } catch (error) {
    showRecoveryMessage(verifyMessage, error instanceof TypeError
      ? 'Unable to reach the password recovery service. Please try again later.'
      : error.message);
    submitButton.disabled = false;
  }
});
