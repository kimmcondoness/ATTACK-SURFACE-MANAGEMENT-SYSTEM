// Keeps the "Monitoring engine" status line live. The engine runs on the server (it does not need
// anyone signed in); this only asks it how it is doing and counts the seconds since its last check.
(function () {
  var box = document.getElementById('monitor-engine');
  var text = document.getElementById('monitor-engine-text');
  if (!box || !text) {
    return;
  }

  var POLL_MS = 15000;
  var engine = null;
  var receivedAt = Date.now();
  var initialAge = box.dataset.age === '' ? null : Number(box.dataset.age);

  function ago(seconds) {
    if (seconds === null) {
      return 'never';
    }
    seconds = Math.max(0, Math.floor(seconds));
    if (seconds < 60) {
      return seconds + 's ago';
    }
    if (seconds < 3600) {
      return Math.floor(seconds / 60) + 'm ago';
    }
    return Math.floor(seconds / 3600) + 'h ago';
  }

  function currentAge() {
    var base = engine ? engine.age_seconds : initialAge;
    return base === null || base === undefined ? null : base + (Date.now() - receivedAt) / 1000;
  }

  function draw() {
    var label = engine ? engine.label : null;
    if (label === null) {
      return;   // nothing newer than the server-rendered line yet
    }
    box.className = 'monitor-engine monitor-engine-' + engine.state;
    var line = label + ' · last check ' + ago(currentAge());
    if (engine.monitored_targets !== undefined) {
      line += ' · ' + engine.monitored_targets + ' target' + (engine.monitored_targets === 1 ? '' : 's') + ' monitored';
    }
    text.textContent = line;
  }

  function poll() {
    fetch(box.dataset.endpoint, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (response) { return response.ok ? response.json() : null; })
      .then(function (data) {
        if (data && data.engine) {
          engine = data.engine;
          receivedAt = Date.now();
          draw();
        }
      })
      .catch(function () { /* offline or signed out: keep what is on screen */ });
  }

  setInterval(poll, POLL_MS);
  setInterval(draw, 1000);
  poll();
})();
