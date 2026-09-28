(function () {
  var confirm = document.querySelector('input[data-confirm-of]');
  if (!confirm) {
    return;
  }
  var password = document.getElementById(confirm.dataset.confirmOf);
  var hint = document.getElementById(confirm.id + '_hint');
  if (!password || !hint) {
    return;
  }

  function check() {
    if (!confirm.value) {
      hint.hidden = true;
      confirm.setCustomValidity('');
      return;
    }
    var matches = confirm.value === password.value;
    hint.hidden = false;
    hint.className = 'match-hint ' + (matches ? 'match-ok' : 'match-bad');
    hint.textContent = matches ? '\u2713 Passwords match.' : '\u2715 Passwords do not match.';
    confirm.setCustomValidity(matches ? '' : 'Passwords do not match.');
  }

  password.addEventListener('input', check);
  confirm.addEventListener('input', check);
})();
