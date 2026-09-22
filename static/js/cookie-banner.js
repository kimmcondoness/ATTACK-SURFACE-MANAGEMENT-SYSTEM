(function () {
  var KEY = 'asm_cookie_notice_ack';
  if (localStorage.getItem(KEY)) {
    return;
  }
  var banner = document.getElementById('cookie-banner');
  banner.hidden = false;

  function ack() {
    localStorage.setItem(KEY, '1');
    banner.hidden = true;
  }

  document.getElementById('cookie-accept').addEventListener('click', ack);
  document.getElementById('cookie-dismiss').addEventListener('click', ack);
})();
