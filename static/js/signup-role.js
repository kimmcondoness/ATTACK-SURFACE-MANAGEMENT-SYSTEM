(function () {
  var accountType = document.getElementById('account_type');
  var roleGroup = document.getElementById('user-role-group');
  var roleSelect = document.getElementById('role');
  var roleAdminHidden = document.getElementById('role_admin');
  if (!accountType) {
    return;
  }

  function sync() {
    var isAdmin = accountType.value === 'it_admin';
    roleGroup.hidden = isAdmin;
    roleSelect.disabled = isAdmin;
    roleAdminHidden.disabled = !isAdmin;
  }

  accountType.addEventListener('change', sync);
  sync();
})();
