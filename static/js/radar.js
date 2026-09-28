(function () {
  var root = document.getElementById('radar-widget');
  var canvas = document.getElementById('radar-canvas');
  if (!root || !canvas || !canvas.getContext) {
    return;
  }

  var ctx = canvas.getContext('2d');
  var pauseBtn = document.getElementById('radar-pause');
  var liveText = document.getElementById('radar-live-text');
  var liveBox = document.getElementById('radar-live');
  var endpoint = root.dataset.endpoint;

  var TAU = Math.PI * 2;
  var SWEEP_SECONDS = 6;          // one full turn
  var TRAIL = 1.15;               // radians of fading glow behind the sweep line
  var POLL_MS = 3000;
  var COLORS = { critical: '#ff5a52', high: '#f0913a', medium: '#e6c229', low: '#5aa7e6', none: '#3fae6a' };
  // Ring position (share of the radius) for each severity: riskiest closest to the centre.
  var RINGS = [
    { key: 'critical', label: 'Critical', at: 0.28 },
    { key: 'high', label: 'High', at: 0.5 },
    { key: 'medium', label: 'Medium', at: 0.72 },
    { key: 'low', label: 'Low / clean', at: 0.94 }
  ];
  var RING_AT = { critical: 0.28, high: 0.5, medium: 0.72, low: 0.94, none: 0.94 };

  var theme = getComputedStyle(document.documentElement);
  var accent = (theme.getPropertyValue('--accent') || '#3fae6a').trim();
  var fontFamily = (theme.getPropertyValue('--sans') || 'sans-serif').trim();
  var reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);

  var state = {
    scope: '',
    nodes: [],
    callouts: [],
    stats: { assets: 0, critical_risks: 0, active_alerts: 0 },
    paused: false,
    scanning: false,
    hover: null,
    pings: [],
    known: null,
    sweep: -Math.PI / 2
  };
  var size = { w: 0, h: 0, dpr: 1 };
  var frame = null;
  var lastTime = 0;
  var pollTimer = null;
  var mouse = null;

  // ---------------------------------------------------------------- data

  function hash(text) {
    var h = 2166136261;
    for (var i = 0; i < text.length; i += 1) {
      h ^= text.charCodeAt(i);
      h = Math.imul(h, 16777619);
    }
    return (h >>> 0) / 4294967296;
  }

  function place(node) {
    // Stable per asset: the same host lands on the same spot after every refresh.
    node.angle = hash(node.host) * TAU;
    node.ring = (RING_AT[node.severity] || RING_AT.none) + (hash(node.host + '#') - 0.5) * 0.1;
  }

  function setText(id, value) {
    var el = document.getElementById(id);
    if (el) {
      el.textContent = value;
    }
  }

  function apply(snapshot, animateNew) {
    if (!snapshot) {
      return;
    }
    var nodes = snapshot.assets || [];
    nodes.forEach(place);

    if (animateNew && state.known) {
      nodes.forEach(function (node) {
        if (!state.known[node.id]) {
          state.pings.push({ node: node, born: performance.now() });
        }
      });
    }
    state.known = {};
    nodes.forEach(function (node) { state.known[node.id] = true; });

    state.scope = snapshot.scope || '';
    state.nodes = nodes;
    state.callouts = snapshot.callouts || [];
    state.stats = snapshot.stats || state.stats;

    setText('radar-stat-assets', state.stats.assets);
    setText('radar-stat-critical', state.stats.critical_risks);
    setText('radar-stat-alerts', state.stats.active_alerts);
    canvas.setAttribute(
      'aria-label',
      'Attack surface radar for ' + state.scope + ': ' + state.stats.assets + ' assets, ' +
        state.stats.critical_risks + ' critical or high risks, ' + state.stats.active_alerts + ' active alerts.'
    );
    renderLive();
    draw(performance.now());
  }

  function currentTargetId() {
    var select = document.getElementById('target-filter');
    return select && select.value ? select.value : '';
  }

  function refresh() {
    if (document.hidden) {
      return Promise.resolve();
    }
    var target = currentTargetId();
    var url = endpoint + (target ? '?target_id=' + encodeURIComponent(target) : '');
    return fetch(url, { headers: { Accept: 'application/json' }, credentials: 'same-origin' })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (data) { apply(data, true); })
      .catch(function () { /* a missed poll just leaves the last picture up */ });
  }

  function renderLive() {
    liveBox.classList.toggle('scanning', state.scanning);
    liveText.textContent = state.scanning ? 'Scanning ' + state.scope : 'Radar idle · ' + state.scope;
  }

  function setScanning(running) {
    if (state.scanning === running) {
      return;
    }
    state.scanning = running;
    renderLive();
    if (running) {
      state.paused = false;
      renderPause();
      start();
      refresh();
      pollTimer = setInterval(refresh, POLL_MS);
    } else {
      stop();
      state.paused = false;
      renderPause();
      clearInterval(pollTimer);
      pollTimer = null;
      draw(performance.now());
      setTimeout(refresh, 600);   // one last look once the scan has stored its final results
    }
  }

  document.addEventListener('scan:state', function (event) {
    setScanning(!!(event.detail && event.detail.running));
  });

  // ---------------------------------------------------------------- drawing

  function resize() {
    var rect = canvas.getBoundingClientRect();
    var dpr = window.devicePixelRatio || 1;
    size.w = Math.max(1, Math.round(rect.width));
    size.h = Math.max(1, Math.round(rect.height));
    size.dpr = dpr;
    canvas.width = Math.round(size.w * dpr);
    canvas.height = Math.round(size.h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(performance.now());
  }

  function geometry() {
    return { cx: size.w / 2, cy: size.h / 2, radius: Math.max(40, Math.min(size.w, size.h) / 2 - 26) };
  }

  function toXY(node, g) {
    return { x: g.cx + Math.cos(node.angle) * node.ring * g.radius, y: g.cy + Math.sin(node.angle) * node.ring * g.radius };
  }

  function angleBehind(sweep, angle) {
    var d = (sweep - angle) % TAU;
    return d < 0 ? d + TAU : d;
  }

  function rgba(hex, alpha) {
    var n = parseInt(hex.slice(1), 16);
    return 'rgba(' + (n >> 16) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + alpha + ')';
  }

  function drawGrid(g) {
    ctx.save();
    ctx.strokeStyle = 'rgba(147, 168, 156, 0.16)';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(g.cx, g.cy - g.radius - 12);
    ctx.lineTo(g.cx, g.cy + g.radius + 12);
    ctx.moveTo(g.cx - g.radius - 12, g.cy);
    ctx.lineTo(g.cx + g.radius + 12, g.cy);
    ctx.stroke();

    ctx.setLineDash([4, 6]);
    RINGS.forEach(function (ring) {
      ctx.beginPath();
      ctx.arc(g.cx, g.cy, ring.at * g.radius, 0, TAU);
      ctx.stroke();
    });
    ctx.setLineDash([]);

    ctx.fillStyle = 'rgba(147, 168, 156, 0.55)';
    ctx.font = '11px ' + fontFamily;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    RINGS.forEach(function (ring) {
      ctx.fillText(ring.label, g.cx, g.cy - ring.at * g.radius - 9);
    });
    ctx.restore();
  }

  function drawSweep(g) {
    var a = state.sweep;
    ctx.save();
    if (ctx.createConicGradient) {
      var grad = ctx.createConicGradient(a - TRAIL, g.cx, g.cy);
      grad.addColorStop(0, rgba('#3fae6a', 0));
      grad.addColorStop(TRAIL / TAU, rgba('#3fae6a', 0.28));
      grad.addColorStop(1, rgba('#3fae6a', 0));
      ctx.fillStyle = grad;
    } else {
      ctx.fillStyle = rgba('#3fae6a', 0.14);
    }
    ctx.beginPath();
    ctx.moveTo(g.cx, g.cy);
    ctx.arc(g.cx, g.cy, g.radius, a - TRAIL, a);
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = accent;
    ctx.lineWidth = 2;
    ctx.shadowColor = accent;
    ctx.shadowBlur = 8;
    ctx.beginPath();
    ctx.moveTo(g.cx, g.cy);
    ctx.lineTo(g.cx + Math.cos(a) * g.radius, g.cy + Math.sin(a) * g.radius);
    ctx.stroke();
    ctx.restore();
  }

  function drawNodes(g, now) {
    var positions = {};
    state.nodes.forEach(function (node) {
      var p = toXY(node, g);
      positions[node.id] = p;

      ctx.strokeStyle = 'rgba(147, 168, 156, 0.10)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(g.cx, g.cy);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
    });

    state.nodes.forEach(function (node) {
      var p = positions[node.id];
      var behind = angleBehind(state.sweep, node.angle);
      var glow = state.scanning && behind < TRAIL ? 1 - behind / TRAIL : 0;
      var color = COLORS[node.severity] || COLORS.none;
      var r = node.severity === 'critical' ? 6 : node.severity === 'high' ? 5 : 4;

      if (glow > 0) {
        ctx.beginPath();
        ctx.fillStyle = rgba(color, 0.22 * glow);
        ctx.arc(p.x, p.y, r + 7 * glow, 0, TAU);
        ctx.fill();
      }
      ctx.beginPath();
      ctx.fillStyle = rgba(color, 0.5 + 0.5 * glow);
      ctx.arc(p.x, p.y, r, 0, TAU);
      ctx.fill();

      if (state.hover === node) {
        ctx.beginPath();
        ctx.strokeStyle = '#eef4ef';
        ctx.lineWidth = 1.5;
        ctx.arc(p.x, p.y, r + 4, 0, TAU);
        ctx.stroke();
      }
    });

    state.pings = state.pings.filter(function (ping) { return now - ping.born < 1400; });
    state.pings.forEach(function (ping) {
      var t = (now - ping.born) / 1400;
      var p = toXY(ping.node, g);
      ctx.beginPath();
      ctx.strokeStyle = rgba(COLORS[ping.node.severity] || COLORS.none, 1 - t);
      ctx.lineWidth = 2;
      ctx.arc(p.x, p.y, 6 + t * 22, 0, TAU);
      ctx.stroke();
    });
    return positions;
  }

  function drawCenter(g) {
    ctx.save();
    ctx.beginPath();
    ctx.fillStyle = rgba('#3fae6a', 0.18);
    ctx.arc(g.cx, g.cy, 13, 0, TAU);
    ctx.fill();
    ctx.beginPath();
    ctx.fillStyle = accent;
    ctx.arc(g.cx, g.cy, 5, 0, TAU);
    ctx.fill();

    if (state.scope) {
      ctx.font = '600 11px ' + fontFamily;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      ctx.fillStyle = 'rgba(238, 244, 239, 0.8)';
      ctx.fillText(state.scope, g.cx, g.cy + 18);
    }
    ctx.restore();
  }

  function overlaps(a, b) {
    return !(a.x + a.w < b.x || b.x + b.w < a.x || a.y + a.h < b.y || b.y + b.h < a.y);
  }

  function drawCallouts(g, positions) {
    var placed = [];
    ctx.save();
    ctx.font = '12px ' + fontFamily;
    ctx.textBaseline = 'middle';
    state.callouts.forEach(function (callout) {
      var p = positions[callout.asset_id];
      if (!p) {
        return;
      }
      var text = callout.title;
      var w = ctx.measureText(text).width + 30;
      var h = 24;
      var right = p.x >= g.cx;
      var candidates = [
        { x: right ? p.x + 16 : p.x - 16 - w, y: p.y - 30 },
        { x: right ? p.x + 16 : p.x - 16 - w, y: p.y + 8 },
        { x: right ? p.x - 16 - w : p.x + 16, y: p.y - 30 },
        { x: right ? p.x - 16 - w : p.x + 16, y: p.y + 8 }
      ];
      var box = candidates[0];
      for (var i = 0; i < candidates.length; i += 1) {
        var c = { x: Math.min(Math.max(4, candidates[i].x), size.w - w - 4), y: Math.min(Math.max(4, candidates[i].y), size.h - h - 4), w: w, h: h };
        if (!placed.some(function (other) { return overlaps(c, other); })) {
          box = c;
          break;
        }
        box = c;
      }
      box.w = w;
      box.h = h;
      placed.push(box);

      var color = COLORS[callout.severity] || COLORS.none;
      ctx.strokeStyle = rgba(color, 0.55);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(box.x + (box.x > p.x ? 0 : w), box.y + h / 2);
      ctx.stroke();

      ctx.fillStyle = 'rgba(12, 18, 16, 0.92)';
      ctx.strokeStyle = rgba(color, 0.7);
      ctx.beginPath();
      if (ctx.roundRect) {
        ctx.roundRect(box.x, box.y, w, h, 5);
      } else {
        ctx.rect(box.x, box.y, w, h);
      }
      ctx.fill();
      ctx.stroke();

      ctx.beginPath();
      ctx.fillStyle = color;
      ctx.arc(box.x + 11, box.y + h / 2, 3.5, 0, TAU);
      ctx.fill();
      ctx.fillStyle = '#eef4ef';
      ctx.textAlign = 'left';
      ctx.fillText(text, box.x + 22, box.y + h / 2 + 0.5);
    });
    ctx.restore();
  }

  function drawTooltip(g, positions) {
    var node = state.hover;
    var p = node && positions[node.id];
    if (!p) {
      return;
    }
    var lines = [
      node.host,
      node.findings + ' live finding' + (node.findings === 1 ? '' : 's') + ' · ' + node.ports + ' open port' + (node.ports === 1 ? '' : 's'),
      'Worst: ' + (node.severity === 'none' ? 'clean' : node.severity)
    ];
    ctx.save();
    ctx.font = '12px ' + fontFamily;
    var w = Math.max.apply(null, lines.map(function (l) { return ctx.measureText(l).width; })) + 20;
    var h = lines.length * 17 + 12;
    var x = Math.min(Math.max(4, p.x + 12), size.w - w - 4);
    var y = Math.min(Math.max(4, p.y + 12), size.h - h - 4);
    ctx.fillStyle = 'rgba(12, 18, 16, 0.96)';
    ctx.strokeStyle = 'rgba(147, 168, 156, 0.5)';
    ctx.fillRect(x, y, w, h);
    ctx.strokeRect(x, y, w, h);
    ctx.fillStyle = '#eef4ef';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'top';
    lines.forEach(function (line, i) { ctx.fillText(line, x + 10, y + 8 + i * 17); });
    ctx.restore();
  }

  function draw(now) {
    if (!size.w) {
      return;
    }
    var g = geometry();
    ctx.clearRect(0, 0, size.w, size.h);
    drawGrid(g);
    if (state.scanning) {
      drawSweep(g);
    }
    var positions = drawNodes(g, now);
    drawCenter(g);
    var hint = null;
    if (!state.nodes.length) {
      hint = state.scanning ? 'Discovering assets...' : 'No assets yet. Start a scan to activate the radar.';
    } else if (!state.scanning) {
      hint = 'Radar idle. Start a scan to activate the sweep.';
    }
    if (hint) {
      ctx.save();
      ctx.fillStyle = 'rgba(147, 168, 156, 0.8)';
      ctx.font = '12px ' + fontFamily;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'alphabetic';
      ctx.fillText(hint, g.cx, state.nodes.length ? size.h - 12 : g.cy - g.radius * 0.5);
      ctx.restore();
    }
    drawCallouts(g, positions);
    drawTooltip(g, positions);
  }

  // ---------------------------------------------------------------- animation

  function tick(time) {
    var seconds = lastTime ? (time - lastTime) / 1000 : 0;
    lastTime = time;
    state.sweep = (state.sweep + (TAU / SWEEP_SECONDS) * seconds) % TAU;
    draw(time);
    frame = requestAnimationFrame(tick);
  }

  function start() {
    if (frame === null && state.scanning && !state.paused && !reduceMotion) {
      lastTime = 0;
      frame = requestAnimationFrame(tick);
    }
  }

  function stop() {
    if (frame !== null) {
      cancelAnimationFrame(frame);
      frame = null;
    }
  }

  var ICON_PAUSE = '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><rect x="6" y="5" width="4" height="14" rx="1"/><rect x="14" y="5" width="4" height="14" rx="1"/></svg>';
  var ICON_PLAY = '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';

  function renderPause() {
    pauseBtn.innerHTML = state.paused ? ICON_PLAY : ICON_PAUSE;
    pauseBtn.setAttribute('aria-pressed', state.paused ? 'true' : 'false');
    pauseBtn.setAttribute('aria-label', state.paused ? 'Resume radar sweep' : 'Pause radar sweep');
    pauseBtn.disabled = !state.scanning;
  }

  pauseBtn.addEventListener('click', function () {
    state.paused = !state.paused;
    renderPause();
    if (state.paused) {
      stop();
      draw(performance.now());
    } else {
      start();
    }
  });

  canvas.addEventListener('mousemove', function (event) {
    var rect = canvas.getBoundingClientRect();
    mouse = { x: event.clientX - rect.left, y: event.clientY - rect.top };
    var g = geometry();
    var best = null;
    var bestDistance = 12;
    state.nodes.forEach(function (node) {
      var p = toXY(node, g);
      var d = Math.hypot(p.x - mouse.x, p.y - mouse.y);
      if (d < bestDistance) {
        best = node;
        bestDistance = d;
      }
    });
    if (best !== state.hover) {
      state.hover = best;
      canvas.style.cursor = best ? 'pointer' : 'default';
      if (frame === null) {
        draw(performance.now());
      }
    }
  });

  canvas.addEventListener('mouseleave', function () {
    state.hover = null;
    if (frame === null) {
      draw(performance.now());
    }
  });

  // ---------------------------------------------------------------- boot

  if (window.ResizeObserver) {
    new ResizeObserver(resize).observe(canvas);
  } else {
    window.addEventListener('resize', resize);
  }

  renderPause();
  resize();

  var initial = document.getElementById('radar-initial-data');
  if (initial) {
    try {
      apply(JSON.parse(initial.textContent), false);
    } catch (e) {
      // no usable snapshot in the page: the first poll (or an empty radar) covers it
    }
  }
  // The sweep stays off until a scan starts (see setScanning); the page shows the last known picture.
})();
