(function () {
  var svg = function (paths) {
    return '<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" ' +
      'stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths + '</svg>';
  };
  var EYE = svg('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>');
  var EYE_OFF = svg(
    '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>' +
    '<path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>' +
    '<path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>'
  );

  document.querySelectorAll('.btn-toggle-password').forEach(function (btn) {
    var input = document.getElementById(btn.dataset.target);
    if (!input) {
      return;
    }

    function render(showing) {
      btn.innerHTML = showing ? EYE_OFF : EYE;
      btn.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
      btn.setAttribute('aria-pressed', showing ? 'true' : 'false');
    }

    render(false);
    btn.addEventListener('click', function () {
      var showing = input.type === 'password';
      input.type = showing ? 'text' : 'password';
      render(showing);
    });
  });
})();
