const accountPanels = document.querySelector('#account-panels');
const accountLoading = document.querySelector('#account-loading');
const accountForms = document.querySelectorAll('[data-account-form]');
const accountCourseList = document.querySelector('#account-course-list');
const accountCourseStatus = document.querySelector('#account-course-status');
const accountPaymentStatus = document.querySelector('#account-payment-status');

function renderEnrolledCourses(courses, paymentRequests = []) {
  const fragment = document.createDocumentFragment();

  accountCourseList.replaceChildren();
  accountCourseStatus.textContent = courses.length === 0
    ? 'You have not enrolled in any courses yet.'
    : `${courses.length} course${courses.length === 1 ? '' : 's'} in your account.`;

  const pending = paymentRequests.filter((request) => request.status === 'pending');
  const rejected = paymentRequests.filter((request) => request.status === 'rejected');
  accountPaymentStatus.textContent = [
    ...pending.map((request) => `Payment for ${request.courseTitle} is awaiting review.`),
    ...rejected.map((request) => `Payment for ${request.courseTitle} was not approved; contact support before trying again.`),
  ].join(' ');

  courses.forEach((course) => {
    const item = document.createElement('li');
    item.className = 'account-course-item';

    const details = document.createElement('div');
    const title = document.createElement('h3');
    title.textContent = course.title;
    const category = document.createElement('p');
    category.textContent = course.category;
    details.append(title, category);

    const removeButton = document.createElement('button');
    removeButton.className = 'account-course-remove';
    removeButton.type = 'button';
    removeButton.textContent = 'Leave course';
    removeButton.addEventListener('click', async () => {
      removeButton.disabled = true;
      accountCourseStatus.textContent = `Removing ${course.title}...`;
      try {
        const response = await fetch(`/api/courses/${course.id}/enrollment`, {
          method: 'DELETE',
          credentials: 'same-origin',
        });
        if (response.status === 401) {
          window.location.replace('/login.html');
          return;
        }
        if (!response.ok) {
          throw new Error('Could not update your course list. Try again.');
        }
        await loadEnrolledCourses();
      } catch (error) {
        accountCourseStatus.textContent = error.message || 'Could not update your course list.';
        removeButton.disabled = false;
      }
    });

    item.append(details, removeButton);
    fragment.append(item);
  });

  accountCourseList.append(fragment);
}

async function loadEnrolledCourses() {
  const response = await fetch('/api/courses/enrollments', { credentials: 'same-origin' });
  if (!response.ok) {
    throw new Error('Could not load your courses. Refresh the page to try again.');
  }
  const { courses, paymentRequests = [] } = await response.json();
  renderEnrolledCourses(courses, paymentRequests);
}

function showFormMessage(form, text, state) {
  const message = form.querySelector('.account-message');
  message.textContent = text;
  message.dataset.state = state;
}

async function loadAccount() {
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
    if (response.status === 401) {
      window.location.replace('/login.html');
      return;
    }
    if (!response.ok) {
      throw new Error('Unable to load your account. Refresh the page to try again.');
    }

    const { user } = await response.json();
    const accountForm = document.querySelector('[data-account-form="account"]');
    accountForm.elements.namedItem('firstName').value = user.first_name;
    accountForm.elements.namedItem('lastName').value = user.last_name;
    accountForm.elements.namedItem('identifier').value = user.identifier;
    accountPanels.hidden = false;
    accountLoading.hidden = true;
    await loadEnrolledCourses();
  } catch {
    accountLoading.textContent = 'We could not load your account. Refresh the page to try again.';
    accountPanels.hidden = false;
    accountCourseStatus.textContent = 'We could not load your courses. Refresh the page to try again.';
  }
}

accountForms.forEach((form) => {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submitButton = form.querySelector('button[type="submit"]');
    const formData = new FormData(form);
    const action = form.dataset.accountForm;
    const payload = Object.fromEntries(formData.entries());

    if (action === 'password' && payload.newPassword !== payload.confirmPassword) {
      showFormMessage(form, 'The new passwords do not match.', 'error');
      return;
    }
    delete payload.confirmPassword;

    submitButton.disabled = true;
    showFormMessage(form, '', '');
    try {
      const response = await fetch(`/api/auth/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify(payload),
      });
      const result = await response.json();
      if (response.status === 401) {
        window.location.replace('/login.html');
        return;
      }
      if (!response.ok) {
        throw new Error(result.error || 'Unable to save your changes.');
      }

      if (action === 'account') {
        form.elements.namedItem('currentPassword').value = '';
        showFormMessage(form, 'Your account details have been saved.', 'success');
      } else {
        form.reset();
        showFormMessage(form, 'Your password has been updated.', 'success');
      }
    } catch (error) {
      showFormMessage(
        form,
        error instanceof TypeError
          ? 'Unable to reach the account service. Please try again.'
          : error.message,
        'error',
      );
    } finally {
      submitButton.disabled = false;
    }
  });
});

loadAccount();
