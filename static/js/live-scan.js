(function () {
  var form = document.getElementById('scan-form');
  if (!form) {
    return;
  }

  var input = document.getElementById('scan-input');
  var runBtn = document.getElementById('scan-run-btn');
  var pauseBtn = document.getElementById('scan-pause-btn');
  var stopBtn = document.getElementById('scan-stop-btn');
  var statusLine = document.getElementById('scan-status-line');
  var csrfToken = document.querySelector('meta[name="csrf-token"]').content;

  var pollTimer = null;
  var chartTimer = null;
  var currentScanId = null;

  var rangePicker = document.getElementById('chart-range-picker');
  var chartRange = (rangePicker && rangePicker.dataset.range) || '12m';

  var targetFilter = document.getElementById('target-filter');
  var chartTargetId = targetFilter && targetFilter.value ? parseInt(targetFilter.value, 10) : null;

  function jsonHeaders() {
    return { 'Content-Type': 'application/json', 'X-CSRFToken': csrfToken };
  }

  function graphql(query, variables) {
    return fetch('/graphql', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ query: query, variables: variables || {} }),
    }).then(function (r) { return r.json(); });
  }

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  }

  function isolateToTarget(targetId, domain) {
    chartTargetId = targetId;
    if (!targetFilter) {
      return;
    }
    var option = targetFilter.querySelector('option[value="' + targetId + '"]');
    if (!option) {
      option = document.createElement('option');
      option.value = String(targetId);
      option.textContent = domain;
      targetFilter.appendChild(option);
    }
    targetFilter.value = String(targetId);

    if (window.history && window.history.pushState) {
      var url = new URL(window.location.href);
      url.searchParams.set('target_id', targetId);
      window.history.pushState({}, '', url);
    }
  }

  function setRunningState(running, paused) {
    runBtn.disabled = running;
    pauseBtn.disabled = !running;
    stopBtn.disabled = !running;
    input.disabled = running;
    pauseBtn.textContent = paused ? 'Resume' : 'Pause';
  }

  // ---- scan lifecycle ----

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var value = input.value.trim();
    if (!value) {
      return;
    }
    statusLine.textContent = 'Starting scan...';
    setRunningState(true, false);

    fetch('/workspace/scan/start', {
      method: 'POST',
      headers: jsonHeaders(),
      body: JSON.stringify({ domain_or_url: value }),
    })
      .then(function (r) { return r.json().then(function (body) { return { ok: r.ok, body: body }; }); })
      .then(function (res) {
        if (!res.ok) {
          statusLine.textContent = 'Error: ' + (res.body.error || 'could not start scan.');
          setRunningState(false, false);
          return;
        }
        currentScanId = res.body.scan_id;
        statusLine.textContent = 'Scanning ' + res.body.domain + '...';
        isolateToTarget(res.body.target_id, res.body.domain);
        startPolling();
        startChartPolling();
      })
      .catch(function () {
        statusLine.textContent = 'Error: could not reach the server.';
        setRunningState(false, false);
      });
  });

  pauseBtn.addEventListener('click', function () {
    if (!currentScanId) {
      return;
    }
    var paused = pauseBtn.textContent === 'Resume';
    var action = paused ? 'resume' : 'pause';
    fetch('/workspace/scan/' + currentScanId + '/' + action, { method: 'POST', headers: jsonHeaders() })
      .then(function (r) { return r.json(); })
      .then(function (body) {
        if (body.status) {
          pauseBtn.textContent = body.status === 'paused' ? 'Resume' : 'Pause';
          statusLine.textContent = body.status === 'paused' ? 'Paused.' : 'Resumed.';
        }
      });
  });

  stopBtn.addEventListener('click', function () {
    if (!currentScanId) {
      return;
    }
    fetch('/workspace/scan/' + currentScanId + '/stop', { method: 'POST', headers: jsonHeaders() })
      .then(function () {
        statusLine.textContent = 'Stopping...';
      });
  });

  // ---- status polling (drives button state) ----

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(pollStatus, 2000);
    pollStatus();
  }

  function stopPolling() {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  var STATUS_QUERY = 'query($id: Int!) { scanStatus(scanId: $id) { status resultSummary source paused } }';

  function pollStatus() {
    if (!currentScanId) {
      return;
    }
    graphql(STATUS_QUERY, { id: currentScanId }).then(function (res) {
      var data = res.data && res.data.scanStatus;
      if (!data) {
        return;
      }
      var terminal = data.status === 'completed' || data.status === 'failed' || data.status === 'stopped';
      setRunningState(!terminal, data.paused);

      if (terminal) {
        stopPolling();
        stopChartPolling();
        refreshCharts();
        var sourceNote = data.source === 'mock' ? ' (mock data — real tool not installed)' : data.source === 'real' ? ' (real scan)' : '';
        statusLine.textContent = 'Finished: ' + data.status + '. ' + (data.resultSummary || '') + sourceNote +
          '. Reloading to show the new rows...';
        setTimeout(function () { window.location.reload(); }, 1800);
      } else {
        statusLine.textContent = (data.paused ? 'Paused' : 'Running') + '... ' + (data.resultSummary || '');
      }
    });
  }

  // ---- donut charts ----

  var themeStyles = getComputedStyle(document.documentElement);
  function themeColor(name) {
    return themeStyles.getPropertyValue(name).trim();
  }

  var COLORS = {
    accent: themeColor('--accent'),
    crit: themeColor('--crit'),
    high: themeColor('--high'),
    med: themeColor('--med'),
    low: themeColor('--low'),
    muted: themeColor('--muted'),
  };

  function makeDonut(canvasId, labels, colors) {
    var canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === 'undefined') {
      return null;
    }
    return new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{ data: labels.map(function () { return 0; }), backgroundColor: colors, borderWidth: 0 }],
      },
      options: {
        cutout: '72%',
        responsive: false,
        animation: { duration: 300 },
        plugins: { legend: { display: false } },
      },
    });
  }

  var scanChart = makeDonut('scan-donut', ['Completed', 'Failed', 'Pending / running'], [COLORS.accent, COLORS.crit, COLORS.muted]);
  var findingChart = makeDonut('finding-donut', ['Critical', 'High', 'Medium', 'Low'], [COLORS.crit, COLORS.high, COLORS.med, COLORS.low]);

  var SCAN_LEGEND = { completed: 'leg-scan-completed', failed: 'leg-scan-failed', other: 'leg-scan-other' };
  var SEVERITY_LEGEND = { critical: 'leg-sev-critical', high: 'leg-sev-high', medium: 'leg-sev-medium', low: 'leg-sev-low' };

  function applyDonutData(chart, totalId, legendMap, totals) {
    var keys = Object.keys(legendMap);
    if (chart) {
      chart.data.datasets[0].data = keys.map(function (k) { return totals[k] || 0; });
      chart.update();
    }
    var sum = 0;
    keys.forEach(function (k) {
      var v = totals[k] || 0;
      sum += v;
      setText(legendMap[k], v);
    });
    setText(totalId, sum);
  }

  function toTotalsMap(segments) {
    var map = {};
    (segments || []).forEach(function (seg) { map[seg.key] = seg.value; });
    return map;
  }

  function updateStatBars(values) {
    var max = Math.max.apply(null, Object.keys(values).map(function (k) { return values[k]; }));
    Object.keys(values).forEach(function (key) {
      var bar = document.getElementById('stat-' + key + '-bar');
      if (bar) {
        bar.style.width = (max ? Math.round((values[key] * 100) / max) : 0) + '%';
      }
    });
  }

  // initial render from server-rendered totals, no network round-trip needed
  var initialDataEl = document.getElementById('chart-initial-data');
  if (initialDataEl) {
    try {
      var initialData = JSON.parse(initialDataEl.textContent);
      applyDonutData(scanChart, 'scan-donut-total', SCAN_LEGEND, initialData.scanStatusTotals);
      applyDonutData(findingChart, 'finding-donut-total', SEVERITY_LEGEND, initialData.severityTotals);
    } catch (e) {
      // malformed/missing initial data just leaves the donuts at zero until the next live refresh
    }
  }

  // ---- range picker ----

  if (rangePicker) {
    rangePicker.querySelectorAll('.chart-range-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        if (btn.dataset.rangeValue === chartRange) {
          return;
        }
        rangePicker.querySelectorAll('.chart-range-btn').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        chartRange = btn.dataset.rangeValue;
        setText('scan-chart-range-label', 'by status · ' + chartRange.toUpperCase());
        setText('finding-chart-range-label', 'by severity · ' + chartRange.toUpperCase());
        refreshCharts();
      });
    });
  }

  // ---- live chart polling ----

  function startChartPolling() {
    stopChartPolling();
    chartTimer = setInterval(refreshCharts, 3000);
  }

  function stopChartPolling() {
    if (chartTimer) {
      clearInterval(chartTimer);
      chartTimer = null;
    }
  }

  var CHARTS_QUERY =
    'query($range: String, $targetId: Int) { liveCharts(range: $range, targetId: $targetId) { totalTargets totalAssets vulnerableCount needsReviewCount riskScore ' +
    'scanStatusTotals { key value } severityTotals { key value } } }';

  function refreshCharts() {
    graphql(CHARTS_QUERY, { range: chartRange, targetId: chartTargetId }).then(function (res) {
      var data = res.data && res.data.liveCharts;
      if (!data) {
        return;
      }
      setText('stat-targets', data.totalTargets);
      setText('stat-assets', data.totalAssets);
      setText('stat-vulnerable', data.vulnerableCount);
      setText('stat-needsreview', data.needsReviewCount);
      setText('stat-risk', data.riskScore);
      updateStatBars({
        targets: data.totalTargets,
        assets: data.totalAssets,
        vulnerable: data.vulnerableCount,
        needsreview: data.needsReviewCount,
        risk: data.riskScore,
      });

      applyDonutData(scanChart, 'scan-donut-total', SCAN_LEGEND, toTotalsMap(data.scanStatusTotals));
      applyDonutData(findingChart, 'finding-donut-total', SEVERITY_LEGEND, toTotalsMap(data.severityTotals));
    });
  }
})();
