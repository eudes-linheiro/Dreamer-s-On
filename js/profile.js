const profileCard = document.querySelector('.profile-card');
const profileStatus = document.querySelector('#profile-status');
const signoutButton = document.querySelector('#signout-button');

function setText(selector, value) {
  document.querySelector(selector).textContent = value;
}

async function loadProfile() {
  try {
    const response = await fetch('/api/auth/me', { credentials: 'same-origin' });
    if (response.status === 401) {
      window.location.replace('/login.html');
      return;
    }
    if (!response.ok) {
      throw new Error('Unable to load your profile. Please try again.');
    }

    const { user } = await response.json();
    const firstName = user.first_name;
    const lastName = user.last_name;
    setText('#profile-name', `${firstName} ${lastName}`);
    setText('#profile-first-name', firstName);
    setText('#profile-last-name', lastName);
    setText('#profile-contact', user.identifier);
    setText('#profile-identifier', user.identifier);
    setText('#profile-avatar', `${firstName[0] || ''}${lastName[0] || ''}`.toUpperCase());
    profileCard.hidden = false;
    profileStatus.hidden = true;
  } catch {
    profileStatus.textContent = 'We could not connect to your account. Refresh the page to try again.';
  }
}

signoutButton.addEventListener('click', async () => {
  signoutButton.disabled = true;
  profileStatus.hidden = false;
  profileStatus.textContent = 'Signing you out...';

  try {
    const response = await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'same-origin',
    });
    if (!response.ok) {
      throw new Error('Sign out failed. Please try again.');
    }
    window.location.replace('/login.html');
  } catch {
    profileStatus.textContent = 'We could not sign you out. Please try again.';
    signoutButton.disabled = false;
  }
});

loadProfile();