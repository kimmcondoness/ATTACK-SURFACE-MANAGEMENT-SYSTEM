// Splits long tables into pages. Mark a table with data-paginate="10" (rows per page);
// the pager is added underneath it and disappears if everything fits on one page.
//
// Works with static/js/table-filter.js: rows the filter has hidden (data-filtered="hide") are left out,
// the pages are worked out from the rows that remain, and a new filter sends the table back to page 1.
(function () {
  var ELLIPSIS = '…';

  function pageList(current, total) {
    // 1 … 4 5 [6] 7 8 … 12  (always the first, last and the pages around the current one)
    var wanted = {};
    [1, total, current - 1, current, current + 1].forEach(function (n) {
      if (n >= 1 && n <= total) {
        wanted[n] = true;
      }
    });
    var numbers = Object.keys(wanted).map(Number).sort(function (a, b) { return a - b; });
    var list = [];
    numbers.forEach(function (n, i) {
      if (i > 0 && n - numbers[i - 1] > 1) {
        list.push(ELLIPSIS);
      }
      list.push(n);
    });
    return list;
  }

  function button(label, page, extraClass, ariaLabel) {
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'pager-btn' + (extraClass ? ' ' + extraClass : '');
    b.textContent = label;
    b.dataset.page = String(page);
    if (ariaLabel) {
      b.setAttribute('aria-label', ariaLabel);
    }
    return b;
  }

  document.querySelectorAll('table[data-paginate]').forEach(function (table) {
    var body = table.tBodies[0];
    if (!body) {
      return;
    }
    var size = parseInt(table.dataset.paginate, 10) || 10;
    var rows = Array.prototype.slice.call(body.rows);
    if (Math.ceil(rows.length / size) <= 1) {
      return;   // filtering can only shrink the table, so it never needs pages
    }

    var current = 1;
    var total = 1;
    var nav = document.createElement('nav');
    nav.className = 'pager';
    nav.setAttribute('aria-label', 'Table pages');
    var info = document.createElement('span');
    info.className = 'pager-info';
    info.setAttribute('aria-live', 'polite');
    var buttons = document.createElement('div');
    buttons.className = 'pager-buttons';
    nav.appendChild(info);
    nav.appendChild(buttons);
    var anchor = table.closest('.table-scroll') || table;
    anchor.parentNode.insertBefore(nav, anchor.nextSibling);

    function render(focusPage) {
      var matching = rows.filter(function (row) { return row.dataset.filtered !== 'hide'; });
      total = Math.max(1, Math.ceil(matching.length / size));
      current = Math.min(current, total);
      var first = (current - 1) * size;
      var onPage = matching.slice(first, first + size);
      rows.forEach(function (row) {
        row.hidden = onPage.indexOf(row) === -1;
      });

      nav.hidden = total <= 1;   // a filter can leave everything on one page
      info.textContent = onPage.length ? 'Showing ' + (first + 1) + '–' + (first + onPage.length) + ' of ' + matching.length : '';

      buttons.textContent = '';
      var prev = button('‹ Prev', current - 1, 'pager-step', 'Previous page');
      prev.disabled = current === 1;
      buttons.appendChild(prev);
      pageList(current, total).forEach(function (item) {
        if (item === ELLIPSIS) {
          var gap = document.createElement('span');
          gap.className = 'pager-gap';
          gap.textContent = ELLIPSIS;
          buttons.appendChild(gap);
          return;
        }
        var b = button(String(item), item, item === current ? 'active' : '', 'Page ' + item);
        if (item === current) {
          b.setAttribute('aria-current', 'page');
        }
        buttons.appendChild(b);
      });
      var next = button('Next ›', current + 1, 'pager-step', 'Next page');
      next.disabled = current === total;
      buttons.appendChild(next);

      // Rebuilding the buttons drops keyboard focus, so put it back on the same control.
      if (focusPage !== undefined) {
        var again = buttons.querySelector('[data-page="' + focusPage + '"]:not(:disabled)') || buttons.querySelector('.active');
        if (again) {
          again.focus();
        }
      }
    }

    buttons.addEventListener('click', function (event) {
      var target = event.target.closest('.pager-btn');
      if (!target || target.disabled) {
        return;
      }
      var page = parseInt(target.dataset.page, 10);
      if (page < 1 || page > total || page === current) {
        return;
      }
      current = page;
      render(page);
    });

    // The filter has just re-marked the rows: start again from the first page of whatever matches.
    table.addEventListener('table-filter', function () {
      current = 1;
      render();
    });

    render();
  });
})();
