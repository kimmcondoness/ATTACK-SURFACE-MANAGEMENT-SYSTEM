(function () {
  var list = document.getElementById('password_rules');
  var input = document.getElementById('password');
  if (!list || !input) {
    return;
  }

  // Same four rules as utils/validators.py; the server is the one that enforces them.
  var rules = {
    length: function (p) { return p.length > 8; },
    upper: function (p) { return /\p{Lu}/u.test(p); },
    number: function (p) { return /[0-9]/.test(p); },
    special: function (p) { return /[^\p{L}\p{N}\s]/u.test(p); }
  };

  function check() {
    var value = input.value;
    var unmet = 0;
    list.querySelectorAll('li').forEach(function (item) {
      var met = rules[item.dataset.rule](value);
      if (!met) {
        unmet += 1;
      }
      item.className = !value ? '' : (met ? 'rule-met' : 'rule-bad');
    });
    input.setCustomValidity(unmet ? 'Password does not meet all the requirements.' : '');
  }

  input.addEventListener('input', check);
  check();
})();
