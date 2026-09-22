(function () {
  var btn = document.getElementById('resend-btn');
  var availableAt = Number(btn.closest('form').dataset.resendAvailableAt) || 0;

  function tick() {
    var remaining = Math.max(0, Math.floor(availableAt - (Date.now() / 1000)));
    if (remaining <= 0) {
      btn.disabled = false;
      btn.textContent = 'Resend code';
      clearInterval(interval);
    } else {
      btn.disabled = true;
      btn.textContent = 'Resend code in ' + remaining + 's';
    }
  }

  var interval = setInterval(tick, 1000);
  tick();
})();
