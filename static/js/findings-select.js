(function () {
  var form = document.getElementById('bulk-delete-form');
  if (!form) {
    return;
  }

  var boxes = Array.prototype.slice.call(document.querySelectorAll('.row-select'));
  var selectAll = document.getElementById('select-all');
  var noCve = document.getElementById('select-no-cve');
  var deleteBtn = document.getElementById('delete-selected');
  var count = document.getElementById('selected-count');
  var search = document.getElementById('table-search');

  function shown(box) {
    return !box.closest('tr').hidden;
  }

  function chosen() {
    return boxes.filter(function (box) {
      return box.checked && shown(box);
    });
  }

  function refresh() {
    var visible = boxes.filter(shown);
    var n = chosen().length;
    count.textContent = n + ' selected';
    deleteBtn.disabled = n === 0;
    selectAll.checked = visible.length > 0 && visible.every(function (box) {
      return box.checked;
    });
  }

  selectAll.addEventListener('change', function () {
    boxes.forEach(function (box) {
      if (shown(box)) {
        box.checked = selectAll.checked;
      }
    });
    refresh();
  });

  noCve.addEventListener('click', function () {
    boxes.forEach(function (box) {
      box.checked = shown(box) && box.dataset.hasCve === 'no';
    });
    refresh();
  });

  boxes.forEach(function (box) {
    box.addEventListener('change', refresh);
  });

  if (search) {
    search.addEventListener('input', refresh);
  }

  form.addEventListener('submit', function (event) {
    var picked = chosen();
    // Rows hidden by the filter must not be deleted by accident.
    boxes.forEach(function (box) {
      if (!shown(box)) {
        box.checked = false;
      }
    });
    var noun = picked.length === 1 ? 'finding' : 'findings';
    if (!window.confirm('Delete ' + picked.length + ' ' + noun + '? This cannot be undone.')) {
      event.preventDefault();
    }
  });

  refresh();
})();
