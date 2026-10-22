const enrollButtons = document.querySelectorAll('[data-course-id]');
const enrollmentPath = '/api/courses/enrollments';
const returnToCourses = encodeURIComponent('/education.html#courses');
const paymentDialog = document.querySelector('#course-payment-dialog');
const paymentForm = document.querySelector('#course-payment-form');
const paymentInstructions = document.querySelector('#course-payment-instructions');
const paymentDialogMessage = document.querySelector('#course-payment-dialog-message');
let activeButton = null;
let paymentDetails;
let paymentDetailsPromise;

function setEnrollmentState(button, enrolled, request) {
  button.dataset.enrolled = String(enrolled);
  button.setAttribute('aria-pressed', String(enrolled));
  if (enrolled) {
    button.textContent = 'Enrolled · leave course';
    button.disabled = false;
  } else if (request?.status === 'pending') {
    button.textContent = 'Payment awaiting review';
    button.disabled = true;
  } else {
    button.textContent = 'Enroll · 3,000 AOA';
    button.disabled = false;
  }
}

function setCourseMessage(button, text, state = '') {
  const card = button.closest('.course-card');
  const message = card.querySelector('[data-course-message]');
  message.textContent = text;
  message.dataset.state = state;
}

async function loadEnrollments() {
  try {
    const response = await fetch(enrollmentPath, { credentials: 'same-origin' });
    if (response.status === 401) {
      enrollButtons.forEach((button) => {
        button.disabled = false;
        button.dataset.authRequired = 'true';
        button.textContent = 'Sign in to enroll';
      });
      return;
    }
    if (!response.ok) {
      throw new Error('Could not load your enrollments. Try again.');
    }

    const { courses, paymentRequests = [] } = await response.json();
    const enrolledIds = new Set(courses.map((course) => course.id));
    const requestsByCourse = new Map(paymentRequests.map((request) => [request.courseId, request]));
    enrollButtons.forEach((button) => {
      const request = requestsByCourse.get(button.dataset.courseId);
      setEnrollmentState(button, enrolledIds.has(button.dataset.courseId), request);
      button.dataset.authRequired = 'false';
      if (request?.status === 'pending') {
        setCourseMessage(button, 'Your payment reference was submitted. Enrollment will be active after review.', 'success');
      } else if (request?.status === 'rejected') {
        setCourseMessage(button, 'Your last payment was not approved. Check with support before resubmitting.', 'error');
      }
    });
  } catch {
    enrollButtons.forEach((button) => {
      button.disabled = false;
      button.textContent = 'Enrollment unavailable';
      setCourseMessage(button, 'Please refresh the page and try again.', 'error');
    });
  }
}

async function fetchPaymentDetails() {
  if (paymentDetails) {
    return paymentDetails;
  }
  if (!paymentDetailsPromise) {
    paymentDetailsPromise = fetch('/api/courses/payment-details', { credentials: 'same-origin' })
      .then(async (response) => {
        if (!response.ok) {
          throw new Error('Course payment details are unavailable. Please contact support.');
        }
        paymentDetails = await response.json();
        return paymentDetails;
      });
  }
  return paymentDetailsPromise;
}

async function openPaymentDialog(button) {
  activeButton = button;
  paymentDialogMessage.textContent = '';
  paymentForm.reset();

  const details = await fetchPaymentDetails();
  if (!details.instructions.trim()) {
    throw new Error('Course payment instructions are not configured. Please contact support.');
  }

  paymentInstructions.textContent = details.instructions;
  paymentDialog.showModal();
  paymentForm.elements.namedItem('transactionReference').focus();
}

const courseButtonHandler = async (event) => {
  const button = event.target.closest('[data-course-id]');
  if (!button) {
    return;
  }

  if (button.dataset.authRequired === 'true') {
    window.location.assign(`/login.html?returnTo=${returnToCourses}`);
    return;
  }
  if (button.disabled) return;
  if (button.dataset.enrolled === 'true') {
    button.disabled = true;
    setCourseMessage(button, 'Updating your course list...');
    try {
      const response = await fetch(`/api/courses/${button.dataset.courseId}/enrollment`, {
        method: 'DELETE',
        credentials: 'same-origin',
      });
      if (response.status === 401) {
        window.location.assign(`/login.html?returnTo=${returnToCourses}`);
        return;
      }
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Could not update your enrollment.');
      await loadEnrollments();
      setCourseMessage(button, 'Course removed from your account.', 'success');
    } catch (error) {
      setCourseMessage(button, error.message || 'Could not update your enrollment. Try again.', 'error');
    } finally {
      button.disabled = false;
    }
    return;
  }

  button.disabled = true;
  try {
    await openPaymentDialog(button);
  } catch (error) {
    setCourseMessage(button, error.message || 'Could not load payment instructions.', 'error');
  } finally {
    button.disabled = false;
  }
};

document.addEventListener('click', courseButtonHandler);

document.querySelector('[data-payment-cancel]').addEventListener('click', () => paymentDialog.close());

paymentForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!activeButton) return;
  const submitButton = paymentForm.querySelector('[type="submit"]');
  submitButton.disabled = true;
  paymentDialogMessage.textContent = 'Submitting your payment reference...';
  try {
    const response = await fetch(`/api/courses/${activeButton.dataset.courseId}/enrollment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({
        transactionReference: paymentForm.elements.namedItem('transactionReference').value,
      }),
    });
    const result = await response.json();
    if (response.status === 401) {
      window.location.assign(`/login.html?returnTo=${returnToCourses}`);
      return;
    }
    if (!response.ok) throw new Error(result.error || 'Could not submit your payment reference.');
    paymentDialog.close();
    await loadEnrollments();
    setCourseMessage(activeButton, 'Payment reference submitted. Enrollment will be active after review.', 'success');
  } catch (error) {
    paymentDialogMessage.textContent = error.message || 'Could not submit your payment reference.';
  } finally {
    submitButton.disabled = false;
  }
});

loadEnrollments();
