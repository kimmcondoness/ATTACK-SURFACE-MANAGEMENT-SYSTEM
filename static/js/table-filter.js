(function () {
  var input = document.getElementById('table-search');
  var table = document.querySelector('table[data-filterable]');
  if (!input || !table) {
    return;
  }

  // Optional second control: a <select id="severity-filter"> matched against each row's data-severity.
  var severity = document.getElementById('severity-filter');
  var rows = Array.prototype.slice.call(table.tBodies[0].rows);
  var noMatch = document.getElementById('table-no-match');
  var count = document.getElementById('table-match-count');

  function apply() {
    var query = input.value.trim().toLowerCase();
    var level = severity ? severity.value : '';
    var shown = 0;
    rows.forEach(function (row) {
      var textHit = !query || (row.dataset.search || row.textContent).toLowerCase().indexOf(query) !== -1;
      var levelHit = !level || row.dataset.severity === level;
      var hit = textHit && levelHit;
      row.hidden = !hit;
      if (hit) {
        shown += 1;
      }
    });
    noMatch.hidden = shown !== 0;
    count.textContent = query || level ? shown + ' of ' + rows.length : '';
  }

  input.addEventListener('input', apply);
  if (severity) {
    severity.addEventListener('change', apply);
  }
})();
