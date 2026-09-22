(function () {
  var select = document.getElementById('target-filter');
  if (!select) {
    return;
  }
  select.addEventListener('change', function () {
    select.form.submit();
  });
})();
