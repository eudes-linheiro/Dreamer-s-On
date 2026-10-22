const enrollButtons = document.querySelectorAll('[data-course-id]');
const enrollmentPath = '/api/courses/enrollments';
const returnToCourses = encodeURIComponent('/education.html#courses');

function setEnrollmentState(button, enrolled) {
  button.dataset.enrolled = String(enrolled);
  button.setAttribute('aria-pressed', String(enrolled));
  button.textContent = enrolled ? 'Enrolled · leave course' : 'Enroll in course';
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

    const { courses } = await response.json();
    const enrolledIds = new Set(courses.map((course) => course.id));
    enrollButtons.forEach((button) => {
      setEnrollmentState(button, enrolledIds.has(button.dataset.courseId));
      button.disabled = false;
      button.dataset.authRequired = 'false';
    });
  } catch {
    enrollButtons.forEach((button) => {
      button.disabled = false;
      button.textContent = 'Enrollment unavailable';
      setCourseMessage(button, 'Please refresh the page and try again.', 'error');
    });
  }
}

enrollButtons.forEach((button) => {
  button.addEventListener('click', async () => {
    if (button.dataset.authRequired === 'true') {
      window.location.assign(`/login.html?returnTo=${returnToCourses}`);
      return;
    }

    const enrolled = button.dataset.enrolled === 'true';
    const method = enrolled ? 'DELETE' : 'POST';
    button.disabled = true;
    setCourseMessage(button, 'Saving your course list...');

    try {
      const response = await fetch(`/api/courses/${button.dataset.courseId}/enrollment`, {
        method,
        credentials: 'same-origin',
      });
      if (response.status === 401) {
        window.location.assign(`/login.html?returnTo=${returnToCourses}`);
        return;
      }
      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.error || 'Could not update your enrollment.');
      }

      setEnrollmentState(button, result.enrolled);
      setCourseMessage(
        button,
        result.enrolled
          ? result.alreadyEnrolled ? 'This course is already in your account.' : 'Course added to your account.'
          : 'Course removed from your account.',
        'success',
      );
    } catch (error) {
      setCourseMessage(button, error.message || 'Could not update your enrollment. Try again.', 'error');
    } finally {
      button.disabled = false;
    }
  });
});

loadEnrollments();