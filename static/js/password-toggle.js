document.querySelectorAll('.btn-toggle-password').forEach(function (btn) {
  var input = document.getElementById(btn.dataset.target);
  btn.addEventListener('click', function () {
    var showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.textContent = showing ? 'Show' : 'Hide';
    btn.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
  });
});
