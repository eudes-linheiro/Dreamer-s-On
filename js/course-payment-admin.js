const statusMessage = document.querySelector('#payment-review-status');
const requestList = document.querySelector('#payment-review-list');

function renderRequests(requests) {
  requestList.replaceChildren();
  if (requests.length === 0) {
    statusMessage.textContent = 'There are no pending course payments to review.';
    return;
  }
  statusMessage.textContent = `${requests.length} payment${requests.length === 1 ? '' : 's'} awaiting review.`;

  requests.forEach((request) => {
    const panel = document.createElement('section');
    panel.className = 'account-panel';
    const heading = document.createElement('div');
    heading.className = 'account-panel-heading';
    const course = document.createElement('h2');
    course.textContent = request.courseTitle;
    const member = document.createElement('p');
    member.textContent = `${request.firstName} ${request.lastName} · ${request.identifier}`;
    const reference = document.createElement('p');
    reference.textContent = `Payment reference: ${request.transactionReference}`;
    const submitted = document.createElement('p');
    submitted.textContent = `Submitted: ${new Date(request.createdAt).toLocaleString()}`;
    heading.append(course, member, reference, submitted);

    const actions = document.createElement('div');
    actions.className = 'account-form-actions';
    ['approve', 'reject'].forEach((action) => {
      const button = document.createElement('button');
      button.className = 'account-submit';
      button.type = 'button';
      button.textContent = action === 'approve' ? 'Approve payment' : 'Reject payment';
      button.addEventListener('click', async () => {
        actions.querySelectorAll('button').forEach((item) => { item.disabled = true; });
        try {
          const response = await fetch(`/api/admin/course-payments/${request.id}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify({ action }),
          });
          const result = await response.json();
          if (!response.ok) throw new Error(result.error || 'Unable to review this payment.');
          await loadRequests();
        } catch (error) {
          statusMessage.textContent = error.message || 'Unable to review this payment.';
          actions.querySelectorAll('button').forEach((item) => { item.disabled = false; });
        }
      });
      actions.append(button);
    });
    panel.append(heading, actions);
    requestList.append(panel);
  });
}

async function loadRequests() {
  try {
    const response = await fetch('/api/admin/course-payments', { credentials: 'same-origin' });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Unable to load payment requests.');
    renderRequests(result.requests);
  } catch (error) {
    requestList.replaceChildren();
    statusMessage.textContent = error.message || 'Unable to load payment requests.';
  }
}

loadRequests();
