document.querySelectorAll('.stat-bar-fill[data-pct]').forEach(function (el) {
  el.style.width = el.dataset.pct + '%';
});
