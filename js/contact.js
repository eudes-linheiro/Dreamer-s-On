const contactForm = document.querySelector('[data-contact-form]');
const contactMessage = document.querySelector('[data-contact-message]');
const contactSubmit = contactForm.querySelector('button[type="submit"]');

contactForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  contactMessage.textContent = '';
  contactMessage.dataset.state = '';
  contactSubmit.disabled = true;

  const formData = new FormData(contactForm);
  const payload = Object.fromEntries(formData.entries());

  try {
    const response = await fetch('/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const result = await response.json();
    if (!response.ok) {
      throw new Error(result.error || 'Unable to send your message. Please try again.');
    }

    contactForm.reset();
    contactMessage.dataset.state = 'success';
    contactMessage.textContent = result.message;
  } catch (error) {
    contactMessage.textContent = error instanceof TypeError
      ? 'Unable to send your message right now. Please try again later.'
      : error.message;
  } finally {
    contactSubmit.disabled = false;
  }
});