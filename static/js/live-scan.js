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

  var progressBox = document.getElementById('scan-progress');
  var progressTrack = document.getElementById('scan-progress-track');
  var progressFill = document.getElementById('scan-progress-fill');
  var phaseEl = document.getElementById('scan-phase');
  var timerEl = document.getElementById('scan-timer');
  var percentEl = document.getElementById('scan-percent');

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

  // ---- live timer + progress bar ----

  var tickTimer = null;
  var elapsedBase = 0;      // seconds the server last told us had passed
  var elapsedSyncedAt = 0;  // when (Date.now) we heard it
  var timerRunning = false;

  function pad(n) {
    return n < 10 ? '0' + n : String(n);
  }

  function formatElapsed(totalSeconds) {
    var s = Math.max(0, Math.floor(totalSeconds));
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    return (h ? h + ':' + pad(m) : pad(m)) + ':' + pad(s % 60);
  }

  function renderTimer() {
    var extra = timerRunning ? (Date.now() - elapsedSyncedAt) / 1000 : 0;
    timerEl.textContent = formatElapsed(elapsedBase + extra);
  }

  // The server is the source of truth (it also knows about time spent paused);
  // between polls the clock just keeps ticking locally so it looks live.
  function syncTimer(seconds, running) {
    elapsedBase = seconds;
    elapsedSyncedAt = Date.now();
    timerRunning = running;
    renderTimer();
  }

  function startTicking() {
    timerEl.classList.remove('finished');
    progressBox.hidden = false;
    if (!tickTimer) {
      tickTimer = setInterval(renderTimer, 250);
    }
  }

  function stopTicking() {
    if (tickTimer) {
      clearInterval(tickTimer);
      tickTimer = null;
    }
    timerRunning = false;
  }

  // state: 'running' | 'paused' | 'completed' | 'failed' | 'stopped'
  function setProgress(percent, phase, state) {
    var known = typeof percent === 'number';
    progressTrack.classList.toggle('indeterminate', !known && state === 'running');
    ['paused', 'completed', 'failed', 'stopped'].forEach(function (s) {
      progressTrack.classList.toggle('state-' + s, s === state);
    });
    progressFill.style.width = known ? percent + '%' : '';
    if (known) {
      progressTrack.setAttribute('aria-valuenow', String(percent));
    } else {
      progressTrack.removeAttribute('aria-valuenow');
    }
    percentEl.textContent = known ? percent + '%' : '';
    phaseEl.textContent = phase;
  }

  function beginProgress() {
    syncTimer(0, true);
    startTicking();
    setProgress(null, 'Starting', 'running');
  }

  // ---- keep the donut charts back until the scan is done ----
  //
  // The radar is the live view while a scan runs. The two donut charts (scan
  // activity, finding trends) only show their result once the scan has finished,
  // so they are held (dimmed, with a note) and not redrawn until then.

  var chartsHeld = false;
  var chartLabelIds = ['scan-chart-range-label', 'finding-chart-range-label'];
  var settledLabels = {};
  chartLabelIds.forEach(function (id) {
    var el = document.getElementById(id);
    settledLabels[id] = el ? el.textContent : '';
  });

  function chartPanels() {
    return chartLabelIds.map(function (id) {
      var el = document.getElementById(id);
      return el ? el.closest('.ws-panel') : null;
    }).filter(Boolean);
  }

  function setChartLabel(id, text) {
    settledLabels[id] = text;
    if (!chartsHeld) {
      setText(id, text);
    }
  }

  function holdCharts(hold) {
    if (chartsHeld === hold) {
      return;
    }
    chartsHeld = hold;
    chartPanels().forEach(function (panel) { panel.classList.toggle('charts-pending', hold); });
    chartLabelIds.forEach(function (id) {
      setText(id, hold ? 'results appear when the scan finishes' : settledLabels[id]);
    });
  }

  function setRunningState(running, paused) {
    holdCharts(running);
    document.dispatchEvent(new CustomEvent('scan:state', { detail: { running: running, paused: paused } }));
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
    beginProgress();

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
          stopTicking();
          progressBox.hidden = true;
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
        stopTicking();
        progressBox.hidden = true;
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

  var STATUS_FIELDS = 'scanId status resultSummary source paused targetDomain elapsedSeconds progressPercent phase';
  var STATUS_QUERY = 'query($id: Int!) { scanStatus(scanId: $id) { ' + STATUS_FIELDS + ' } }';
  var ACTIVE_QUERY = 'query { activeScan { ' + STATUS_FIELDS + ' } }';

  function applyProgress(data, terminal) {
    if (terminal) {
      syncTimer(data.elapsedSeconds, false);
      stopTicking();
      timerEl.classList.add('finished');
      var label = data.status === 'completed' ? 'Completed' : data.status === 'failed' ? 'Failed' : 'Stopped';
      setProgress(data.status === 'completed' ? 100 : data.progressPercent, label + ' in ' + formatElapsed(data.elapsedSeconds), data.status);
      return;
    }
    syncTimer(data.elapsedSeconds, !data.paused);
    startTicking();
    setProgress(data.progressPercent, data.paused ? 'Paused \u00b7 ' + data.phase : data.phase, data.paused ? 'paused' : 'running');
  }

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
      applyProgress(data, terminal);

      if (terminal) {
        stopPolling();
        stopChartPolling();
        refreshCharts();
        setTimeout(refreshCharts, 1200);   // a second look in case the first request was unlucky
        var sourceNote = data.source === 'mock' ? ' (mock data — real tool not installed)' : data.source === 'real' ? ' (real scan)' : '';
        statusLine.textContent = 'Finished: ' + data.status + '. ' + (data.resultSummary || '') + sourceNote +
          '. Reloading to show the new rows...';
        setTimeout(function () { window.location.reload(); }, 3500);
      } else {
        statusLine.textContent = (data.paused ? 'Paused' : 'Running') + '... ' + (data.resultSummary || '');
      }
    });
  }

  // A scan keeps running on the server if the page is reloaded or reopened, so
  // pick it up again instead of showing an idle panel with a live Run button.
  graphql(ACTIVE_QUERY).then(function (res) {
    var data = res.data && res.data.activeScan;
    if (!data || currentScanId) {
      return;
    }
    currentScanId = data.scanId;
    input.value = data.targetDomain;
    statusLine.textContent = (data.paused ? 'Paused' : 'Running') + '... ' + (data.resultSummary || '');
    setRunningState(true, data.paused);
    applyProgress(data, false);
    startPolling();
    startChartPolling();
  });

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
        setChartLabel('scan-chart-range-label', 'by status · ' + chartRange.toUpperCase());
        setChartLabel('finding-chart-range-label', 'by severity · ' + chartRange.toUpperCase());
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

  var chartRequest = 0;

  function refreshCharts() {
    var mine = chartRequest += 1;
    graphql(CHARTS_QUERY, { range: chartRange, targetId: chartTargetId }).then(function (res) {
      var data = res.data && res.data.liveCharts;
      if (!data && window.console) {
        console.warn('Chart refresh returned no data', res.errors || res);
      }
      // A slower, older response must not overwrite a newer one (e.g. the final result).
      if (!data || mine !== chartRequest) {
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

      if (chartsHeld) {
        return;
      }
      applyDonutData(scanChart, 'scan-donut-total', SCAN_LEGEND, toTotalsMap(data.scanStatusTotals));
      applyDonutData(findingChart, 'finding-donut-total', SEVERITY_LEGEND, toTotalsMap(data.severityTotals));
    }).catch(function (error) {
      if (window.console) {
        console.warn('Chart refresh failed', error);
      }
    });
  }

  // Whenever no scan is running the charts must show the saved results. The numbers
  // embedded in the page normally cover that; asking the server once more on load makes
  // sure a missing or unreadable snapshot can never leave the charts empty.
  refreshCharts();
})();
