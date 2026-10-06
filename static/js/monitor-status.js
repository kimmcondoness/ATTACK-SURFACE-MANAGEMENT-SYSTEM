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

  // What the engine is working on: nothing (idle), or how many targets, and how many are the viewer's own.
  function workText(e) {
    if (e.state === 'idle') {
      return 'no monitoring is turned on';
    }
    if (e.state !== 'active') {
      return '';
    }
    var line = e.monitored_targets + ' target' + (e.monitored_targets === 1 ? '' : 's') + ' monitored';
    if (e.other_monitored_targets > 0) {
      line += ': ' + e.your_monitored_targets + ' yours, ' + e.other_monitored_targets + ' by other users';
    }
    return line;
  }

  function draw() {
    if (engine === null) {
      return;   // nothing newer than the server-rendered line yet
    }
    box.className = 'monitor-engine monitor-engine-' + engine.state;
    var parts = [engine.label, 'last check ' + ago(currentAge()), workText(engine)];
    if (engine.started_at && (engine.state === 'active' || engine.state === 'idle')) {
      parts.push('running since ' + engine.started_at.slice(0, 16).replace('T', ' ') + ' UTC');
    }
    text.textContent = parts.filter(Boolean).join(' · ');
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
