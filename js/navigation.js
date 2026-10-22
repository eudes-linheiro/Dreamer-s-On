document.querySelectorAll('[data-menu-toggle]').forEach((button) => {
  const navigation = button.closest('nav');
  if (!navigation) return;

  const setExpanded = (expanded) => {
    navigation.classList.toggle('is-open', expanded);
    button.setAttribute('aria-expanded', String(expanded));
    button.setAttribute('aria-label', expanded ? 'Close navigation' : 'Open navigation');
  };

  button.addEventListener('click', () => {
    setExpanded(button.getAttribute('aria-expanded') !== 'true');
  });

  navigation.addEventListener('click', (event) => {
    if (event.target.closest('a')) setExpanded(false);
  });

  navigation.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      setExpanded(false);
      button.focus();
    }
  });
});
