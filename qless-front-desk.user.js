// ==UserScript==
// @name         Qless Front Desk Assistant
// @namespace    qless-front-desk
// @version      2.3.0
// @description  Hands-free iPhone voice check-in, live assistant tips, CWID auto-fill, shortcuts and a daily counter for Qless
// @match        *://merchant.qless.com/*
// @require      https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js
// @grant        none
// @run-at       document-idle
// @downloadURL  https://cookiikid.github.io/front-desk/qless-front-desk.user.js
// @updateURL    https://cookiikid.github.io/front-desk/qless-front-desk.user.js
// ==/UserScript==

/* Replaces "Qless CWID Auto-Filler V5" (same CWID behaviour is built in below) — disable V5. */
(function () {
  'use strict';

  /* QRelay — tiny end-to-end encrypted pub/sub between the phone and the PC.
   * Talks MQTT 3.1.1 over WebSocket to two free public brokers at once (redundancy),
   * and AES-GCM encrypts every message with a key that only the phone + PC know,
   * so the brokers only ever see random-looking ciphertext. */
  var QRelay = (function () {
    'use strict';
    var BROKERS = ['wss://broker.hivemq.com:8884/mqtt', 'wss://broker.emqx.io:8084/mqtt'];
    var te = new TextEncoder(), td = new TextDecoder();
  
    function b64u(bytes) {
      var s = '';
      for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
      return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }
    function unb64u(str) {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      var s = atob(str), out = new Uint8Array(s.length);
      for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    }
    function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }
    function newPairing() { return { topic: b64u(rand(12)), key: b64u(rand(32)) }; }
    function encodePairing(p) { return p.topic + '.' + p.key; }
    function decodePairing(s) {
      var m = /^([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{43})$/.exec((s || '').trim());
      return m ? { topic: m[1], key: m[2] } : null;
    }
  
    // ---------- minimal MQTT 3.1.1 packet codec ----------
    function concat(arrs) {
      var n = 0, i = 0;
      arrs.forEach(function (a) { n += a.length; });
      var o = new Uint8Array(n);
      arrs.forEach(function (a) { o.set(a, i); i += a.length; });
      return o;
    }
    function encStr(s) {
      var b = typeof s === 'string' ? te.encode(s) : s;
      return concat([new Uint8Array([b.length >> 8, b.length & 255]), b]);
    }
    function packet(type, body) {
      var len = [], x = body.length;
      do { var d = x % 128; x = Math.floor(x / 128); if (x > 0) d |= 128; len.push(d); } while (x > 0);
      return concat([new Uint8Array([type]), new Uint8Array(len), body]);
    }
    function connectPkt(clientId, will) {
      var flags = 0x02; // clean session
      var parts = [encStr('MQTT'), new Uint8Array([4]), null, new Uint8Array([0, 30]), encStr(clientId)];
      if (will) {
        flags |= 0x04 | (will.retain ? 0x20 : 0);
        parts.push(encStr(will.topic), encStr(will.payload));
      }
      parts[2] = new Uint8Array([flags]);
      return packet(0x10, concat(parts));
    }
    function subscribePkt(id, topics) {
      var parts = [new Uint8Array([id >> 8, id & 255])];
      topics.forEach(function (t) { parts.push(encStr(t), new Uint8Array([0])); });
      return packet(0x82, concat(parts));
    }
    function publishPkt(topic, payload, retain) {
      return packet(0x30 | (retain ? 1 : 0), concat([encStr(topic), te.encode(payload)]));
    }
  
    // ---------- one broker connection with auto-reconnect ----------
    function Conn(url, opts) {
      this.url = url; this.opts = opts; this.ready = false; this.backoff = 1000;
      this.buf = new Uint8Array(0); this.stopped = false;
      this.open();
    }
    Conn.prototype.open = function () {
      var self = this;
      if (self.stopped) return;
      var ws;
      try { ws = new WebSocket(self.url, 'mqtt'); } catch (e) { return self.retry(); }
      self.ws = ws; ws.binaryType = 'arraybuffer';
      ws.onopen = function () {
        self.buf = new Uint8Array(0);
        ws.send(connectPkt('qfd' + b64u(rand(9)), self.opts.will));
      };
      ws.onmessage = function (ev) { self.feed(new Uint8Array(ev.data)); };
      ws.onclose = function () { self.setReady(false); clearInterval(self.ping); self.retry(); };
      ws.onerror = function () { try { ws.close(); } catch (e) {} };
    };
    Conn.prototype.retry = function () {
      var self = this;
      if (self.stopped || self.retryTimer) return;
      self.retryTimer = setTimeout(function () { self.retryTimer = null; self.open(); }, self.backoff);
      self.backoff = Math.min(self.backoff * 2, 15000);
    };
    Conn.prototype.setReady = function (r) {
      if (this.ready !== r) { this.ready = r; this.opts.onReady(); }
    };
    Conn.prototype.feed = function (chunk) {
      this.buf = concat([this.buf, chunk]);
      for (;;) {
        var b = this.buf;
        if (b.length < 2) return;
        var mult = 1, len = 0, i = 1, d;
        do {
          if (i >= b.length) return;
          d = b[i++]; len += (d & 127) * mult; mult *= 128;
        } while (d & 128);
        if (b.length < i + len) return;
        this.handle(b[0], b.subarray(i, i + len));
        this.buf = b.slice(i + len);
      }
    };
    Conn.prototype.handle = function (h, body) {
      var self = this, type = h >> 4;
      if (type === 2) { // CONNACK
        if (body[1] !== 0) { try { self.ws.close(); } catch (e) {} return; }
        self.backoff = 1000;
        self.ws.send(subscribePkt(1, self.opts.subs));
        (self.opts.onConnect || []).forEach(function (p) { self.ws.send(publishPkt(p.topic, p.payload, p.retain)); });
        clearInterval(self.ping);
        self.ping = setInterval(function () { self.send(new Uint8Array([0xC0, 0])); }, 20000);
        self.setReady(true);
      } else if (type === 3) { // PUBLISH
        var qos = (h >> 1) & 3, tlen = (body[0] << 8) | body[1];
        var topic = td.decode(body.subarray(2, 2 + tlen)), p = 2 + tlen;
        if (qos > 0) {
          var pid = body.subarray(p, p + 2); p += 2;
          if (qos === 1) self.send(concat([new Uint8Array([0x40, 2]), pid]));
        }
        self.opts.onPublish(topic, td.decode(body.subarray(p)), !!(h & 1));
      }
    };
    Conn.prototype.send = function (bytes) {
      if (this.ws && this.ws.readyState === 1) { this.ws.send(bytes); return true; }
      return false;
    };
    Conn.prototype.publish = function (topic, payload, retain) {
      return this.ready && this.send(publishPkt(topic, payload, retain));
    };
    Conn.prototype.close = function () {
      this.stopped = true; clearInterval(this.ping); clearTimeout(this.retryTimer);
      try { this.ws.send(new Uint8Array([0xE0, 0])); this.ws.close(); } catch (e) {}
    };
    // Reconnect right away (e.g. when the phone screen wakes up).
    Conn.prototype.kick = function () {
      if (this.stopped) return;
      if (!this.ws || this.ws.readyState > 1) { clearTimeout(this.retryTimer); this.retryTimer = null; this.backoff = 1000; this.open(); }
    };
  
    // ---------- encrypted relay ----------
    function Relay(o) {
      var self = this;
      self.o = o; self.role = o.role; self.peer = o.peer || (o.role === 'pc' ? 'phone' : 'pc');
      self.base = 'qfd/' + o.topic + '/';
      self.seen = []; self.peerOnline = {}; self.lastStateTs = 0;
      self.keyP = crypto.subtle.importKey('raw', unb64u(o.key), 'AES-GCM', false, ['encrypt', 'decrypt']);
      var onlineTopic = self.base + self.role + '/online';
      self.conns = BROKERS.map(function (url) {
        return new Conn(url, {
          subs: [self.base + self.peer + '/msg', self.base + self.peer + '/online'],
          will: { topic: onlineTopic, payload: '0', retain: true },
          onConnect: [{ topic: onlineTopic, payload: '1', retain: true }],
          onReady: function () { self.emitStatus(); },
          onPublish: function (topic, payload) { self.receive(url, topic, payload); }
        });
      });
    }
    Relay.prototype.status = function () {
      var self = this;
      return {
        brokers: self.conns.filter(function (c) { return c.ready; }).length,
        peerOnline: self.conns.some(function (c) { return c.ready && self.peerOnline[c.url]; })
      };
    };
    Relay.prototype.emitStatus = function () { if (this.o.onStatus) this.o.onStatus(this.status()); };
    Relay.prototype.receive = function (url, topic, payload) {
      var self = this;
      if (/\/online$/.test(topic)) { self.peerOnline[url] = payload === '1'; self.emitStatus(); return; }
      self.keyP.then(function (key) {
        var raw = unb64u(payload);
        return crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, key, raw.subarray(12));
      }).then(function (plain) {
        var msg = JSON.parse(td.decode(plain));
        if (self.seen.indexOf(msg.mid) >= 0) return; // same message via the other broker
        self.seen.push(msg.mid); if (self.seen.length > 200) self.seen.shift();
        if (msg.t === 'state') {
          if (msg.ts < self.lastStateTs) return;
          self.lastStateTs = msg.ts;
        } else if (Date.now() - msg.ts > 120000) return; // ignore stale commands
        self.o.onMessage(msg);
      }).catch(function () { /* not ours / wrong key */ });
    };
    Relay.prototype.send = function (obj, retain) {
      var self = this;
      obj.mid = b64u(rand(9)); obj.ts = Date.now();
      var iv = rand(12);
      return self.keyP.then(function (key) {
        return crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, te.encode(JSON.stringify(obj)));
      }).then(function (ct) {
        var payload = b64u(concat([iv, new Uint8Array(ct)]));
        var sent = 0;
        self.conns.forEach(function (c) { if (c.publish(self.base + self.role + '/msg', payload, retain)) sent++; });
        return sent;
      });
    };
    Relay.prototype.kick = function () { this.conns.forEach(function (c) { c.kick(); }); };
    Relay.prototype.close = function () {
      var t = this.base + this.role + '/online';
      this.conns.forEach(function (c) { c.publish(t, '0', true); c.close(); });
    };
  
    return { Relay: Relay, newPairing: newPairing, encodePairing: encodePairing, decodePairing: decodePairing };
  })();
  

  /* QKB — the front-desk knowledge base: instant tips from what's being said.
   * kb.json (private) is published only as AES-GCM ciphertext (kb.enc); the key lives on the PC + phone. */
  var QKB = (function () {
    'use strict';
    var kb = null, index = [];
  
    function unb64u(str) {
      str = str.replace(/-/g, '+').replace(/_/g, '/');
      while (str.length % 4) str += '=';
      var s = atob(str), out = new Uint8Array(s.length);
      for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
      return out;
    }
    async function decrypt(b64, keyB64u) {
      var raw = unb64u(b64.trim());
      var key = await crypto.subtle.importKey('raw', unb64u(keyB64u), 'AES-GCM', false, ['decrypt']);
      var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12) }, key, raw.subarray(12));
      return JSON.parse(new TextDecoder().decode(plain));
    }
  
    // Words speech recognition gets wrong in this lobby (heard -> meant).
    var SOUNDALIKE = [[/\bboating\b/g, 'voting'], [/\bboat\b(?= (?:at|here|today|early))/g, 'vote'], [/\b(?:quoting|floating|noting)(?= (?:location|booth|center|at|today))/g, 'voting'],
      [/\bt s i\b|\btea s i\b|\bt\.s\.i\.?/g, 'tsi'], [/\bfafsa's\b|\bfasa\b|\bfafsa\b|\bfaf sa\b|\bfaff sa\b/g, 'fafsa'], [/\bhazel ?wood\b/g, 'hazlewood'],
      [/\bmeningitis\b|\bmenengitis\b/g, 'meningitis'], [/\bc ?w ?i ?d\b/g, 'cwid']];
    function fixHeard(s) { s = String(s || '').toLowerCase(); SOUNDALIKE.forEach(function (r) { s = s.replace(r[0], r[1]); }); return s; }
    // lowercase, no accents/punctuation, plural "s" dropped so "transcripts" matches "transcript"
    function norm(s) {
      return ' ' + fixHeard(s).normalize('NFD').replace(/[̀-ͯ]/g, '')
        .replace(/[^a-z0-9+@.\s]/g, ' ').replace(/\.+(\s|$)/g, ' ').split(/\s+/).filter(Boolean)
        .map(function (w) { return w.length > 3 && /[^s]s$/.test(w) ? w.slice(0, -1) : w; }).join(' ') + ' ';
    }
  
    // ---------- walking directions from the Campus Commons front desk ----------
    var FLOOR = ['', '1st', '2nd', '3rd', '4th'];
    var SC_ROUTE = 'Go around this corner, then out the double doors to the building behind us — that\'s the Student Center';
    function route(b, floor, room) {
      var f = FLOOR[floor] || '';
      if (b === 'CC') {
        if (floor === 1) return 'Right here in this building (Campus Commons), this floor — room ' + room + '.';
        if (floor === 2) return 'Upstairs — 2nd floor of this building (Campus Commons), room ' + room + (/^20\d/.test(room) ? ', basically right above us.' : '.');
        return f + ' floor of this building (Campus Commons), room ' + room + '.';
      }
      if (b === 'SC') return SC_ROUTE + (floor > 1 ? '; ' + f + ' floor, room ' + room + '.' : '; room ' + room + ' on the ground floor.');
      if (b === 'L') return 'Library building (WLB)' + (kb && kb.libraryRoute ? ' — ' + kb.libraryRoute : '') + '; ' + (floor > 1 ? f + ' floor, ' : 'ground floor, ') + 'room ' + room + '.';
      return '';
    }
    // "WSC 330", "SC-330", "CC 215F", "WLB 206", "library 206", "student center 113", "campus commons 2 15"
    var ROOM_RE = /\b(w?cc|w?sc|wlb|campus commons|student center|library)[\s-]*([1-3])\s*(\d\d)([a-f])?\b/i;
    function roomCard(text) {
      var m = ROOM_RE.exec(String(text || '').split(/\s+/).slice(-30).join(' ').replace(/\b(w?[cs]c)\s+(\d)\s+(\d)\s*(\d)\b/ig, '$1 $2$3$4'));
      if (!m) return null;
      var k = m[1].toLowerCase().replace(/^w(?=cc|sc)/, '');
      var b = /cc|commons/.test(k) ? 'CC' : /sc|student/.test(k) ? 'SC' : 'L';
      var room = m[2] + m[3] + (m[4] || '').toUpperCase(), floor = Number(m[2]);
      var name = { CC: 'Campus Commons', SC: 'Student Center', L: 'Library' }[b];
      return { id: 'room:' + b + room, kind: 'place', title: name + ' ' + room, say: route(b, floor, room), facts: [], queue: null, map: b + '-' + room };
    }
    function today() { var d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
    var WHERE_RE = /\b(where|wheres|how do i get|how do i find|how to get|location|located|which building|what building|what room|donde|dónde)\b/i;
  
    function load(data) {
      kb = data; index = [];
      (kb.places || []).forEach(function (pl) {
        kb.cards.push({ id: 'place-' + pl.id, kind: 'place', title: pl.name + (pl.room && pl.b !== 'off' ? ' — ' + (pl.b === 'L' ? 'Library ' : pl.b + ' ') + pl.room : ''),
          say: pl.say || route(pl.b, pl.floor, pl.room), facts: pl.facts || [], triggers: pl.triggers, until: pl.until, map: pl.map || null });
      });
      (kb.cards || []).forEach(function (c) {
        index.push({ card: c, triggers: (c.triggers || []).map(function (t) { return norm(t); }) });
      });
      (kb.staff || []).forEach(function (p) {
        var n = norm(p.name);
        if (n.trim().split(' ').length < 2) return; // full names only, to avoid false hits
        index.push({
          card: { id: 'staff:' + p.name, kind: 'staff', title: p.name, say: p.title + (p.where ? ' — ' + p.where : ''), facts: [p.phone, p.email].filter(Boolean) },
          triggers: [n]
        });
      });
      return kb;
    }
  
    function upcoming(days, re) {
      if (!kb || !kb.dates) return [];
      var now = new Date(); now.setHours(0, 0, 0, 0);
      var end = new Date(now.getTime() + days * 864e5);
      return kb.dates.filter(function (d) {
        var t = new Date(d.date + 'T00:00:00');
        return t >= now && t <= end && (!re || new RegExp(re, 'i').test(d.label));
      });
    }
    function fmtDate(iso) {
      var d = new Date(iso + 'T00:00:00');
      return d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric' });
    }
  
    // text -> best cards. Recent words count more (the last ~25 words are what's being talked about now).
    // opts.skip: regex of card ids to leave out (e.g. the "find your CWID" card once we already have it)
    function match(text, max, opts) {
      if (!kb) return [];
      var skip = opts && opts.skip;
      var all = norm(text), recentRaw = String(text || '').split(/\s+/).slice(-25).join(' '), recent = norm(recentRaw);
      var asking = WHERE_RE.test(recentRaw), now = today(), scored = [];
      index.forEach(function (e) {
        if (e.card.until && e.card.until < now) return;
        var s = 0;
        e.triggers.forEach(function (t) {
          if (all.indexOf(t) >= 0) s += t.length > 12 ? 3 : 2;
          if (recent.indexOf(t) >= 0) s += 1;
        });
        if (e.card.kind === 'place' && s) s += asking ? 6 : -1; // "where is…" -> directions first
        if (s > 0 && !(skip && skip.test(e.card.id))) scored.push({ s: s + (e.card.priority || 0), card: e.card });
      });
      var rc = roomCard(text);
      if (rc) scored.push({ s: 100, card: rc });
      scored.sort(function (a, b) { return b.s - a.s; });
      return scored.slice(0, max || 2).map(function (x) { return render(x.card); });
    }
    function byId(id) {
      if (/^room:/.test(id)) { var m = /^room:(CC|SC|L)(\d)(\d\d[A-F]?)$/.exec(id); return m ? roomCard({ CC: 'CC ', SC: 'SC ', L: 'library ' }[m[1]] + m[2] + m[3]) : null; }
      var e = index.filter(function (x) { return x.card.id === id; })[0];
      return e ? render(e.card) : null;
    }
    // Attach live dates (e.g. next withdraw deadline) to a card.
    function render(c) {
      var out = { id: c.id, kind: c.kind || 'tip', title: c.title, say: c.say, facts: (c.facts || []).slice(), queue: c.queue || null, map: c.map || null };
      if (c.dates) upcoming(400, c.dates).slice(0, 3).forEach(function (d) { out.facts.push(fmtDate(d.date) + ': ' + d.label); });
      return out;
    }
  
    // Typed search box: every word must prefix-match something on the card (title counts most).
    function search(q, max) {
      if (!kb) return [];
      var STOP = /^(where|wheres|is|the|a|an|to|how|do|does|i|get|find|my|for|of|in|at|what|can|you|me|go|please|need|want|it|on|and|or|about|with)$/;
      var words = norm(q).trim().split(' ').filter(function (w) { return (w.length > 1 || /\d/.test(w)) && !STOP.test(w); });
      if (!words.length) return [];
      var out = [], rc = roomCard(q);
      if (rc) out.push({ s: 100, card: rc });
      var now = today();
      index.forEach(function (e) {
        var c = e.card;
        if (c.until && c.until < now) return;
        var title = norm(c.title), trig = e.triggers.join(' '), body = norm((c.say || '') + ' ' + (c.facts || []).join(' '));
        var s = 0, missed = 0;
        words.forEach(function (w) {
          var re = new RegExp(' ' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
          var hit = re.test(title) ? 4 : re.test(trig) ? 3 : re.test(body) ? 1 : 0;
          if (!hit) missed++;
          s += hit;
        });
        if (s && missed <= (words.length > 2 ? 1 : words.length > 1 ? 1 : 0) && missed < words.length) out.push({ s: s + (c.kind === 'place' ? 1 : 0) + (c.priority || 0), card: c });
      });
      out.sort(function (a, b) { return b.s - a.s; });
      return out.slice(0, max || 6).map(function (x) { return x.card.kind === 'place' && /^room:/.test(x.card.id) ? x.card : render(x.card); });
    }
  
    return {
      search: search, fixHeard: fixHeard,
      decrypt: decrypt, load: load, match: match, byId: byId, upcoming: upcoming, fmtDate: fmtDate,
      keyterms: function () { return (kb && kb.keyterms) || []; },
      loaded: function () { return !!kb; },
      version: function () { return kb && kb.version; }
    };
  })();
  

  /* QMaps — indoor wayfinding for the front desk.
   *   QMaps.load({ buildings: [CC, SC, L], campus })   build one graph (all floors, all buildings)
   *   QMaps.find("where is WCC 200?")                    -> { id, building, floor, label } | null
   *   QMaps.route(toId, { from, avoidStairs })           -> { legs, steps, meters, minutes, summary }
   *   QMaps.render(el, route, { edit, onPick })          draws the map card (SVG, scoped under .qmap)
   *   QMaps.setDesk(nodeIdOrXY)                          move "You are here"
   * Plain ES5, no dependencies. Data schema: kb/maps/SCHEMA.md
   */
  var QMaps = (function () {
    'use strict';
  
    var CFG = {
      metersPerUnit: 0.12,      // 1000 canvas units ~ 120 m (per building: "metersPer1000" or "metersPerUnit")
      stairMeters: 25,          // cost of one floor by stairs
      elevatorMeters: 40,       // cost of one floor by elevator (waiting included)
      outdoorMeters: 60,        // default length of a campus link without "meters"
      walkMetersPerMin: 75,
      autoAdvanceMs: 3500,
      mapHeight: 320
    };
  
    /* ------------------------------------------------------------------ state */
    var B, BLIST, FLOORS, N, ADJ, ROOMS, ROOMIDX, DOORS, TARGETS, TKEY, ENTR, CAMPUS, DESK, DIST, DEFAULT_B;
    function reset() {
      B = {}; BLIST = []; FLOORS = {}; N = {}; ADJ = {}; ROOMS = {}; ROOMIDX = {}; DOORS = {};
      TARGETS = {}; TKEY = {}; ENTR = {}; CAMPUS = { links: [], layout: null }; DESK = null; DIST = null; DEFAULT_B = null;
    }
    reset();
  
    /* --------------------------------------------------------------- geometry */
    function sub(a, b) { return [a[0] - b[0], a[1] - b[1]]; }
    function cross(a, b) { return a[0] * b[1] - a[1] * b[0]; }
    function dot(a, b) { return a[0] * b[0] + a[1] * b[1]; }
    function len(v) { return Math.sqrt(v[0] * v[0] + v[1] * v[1]); }
    function dist(a, b) { return len(sub(a, b)); }
    function unit(v) { var l = len(v) || 1; return [v[0] / l, v[1] / l]; }
    // signed turn in degrees at b going a->b->c; positive = right (canvas y points down)
    function turnDeg(a, b, c) {
      var v1 = sub(b, a), v2 = sub(c, b);
      return Math.atan2(cross(v1, v2), dot(v1, v2)) * 180 / Math.PI;
    }
    function angleBetween(h1, h2) { return Math.atan2(cross(h1, h2), dot(h1, h2)) * 180 / Math.PI; }
    function segProject(p, a, b) {
      var ab = sub(b, a), l2 = dot(ab, ab), t = l2 ? dot(sub(p, a), ab) / l2 : 0;
      t = Math.max(0, Math.min(1, t));
      var q = [a[0] + ab[0] * t, a[1] + ab[1] * t];
      return { t: t, x: q[0], y: q[1], d: dist(p, q) };
    }
    function rectPoly(r) { return [[r[0], r[1]], [r[0] + r[2], r[1]], [r[0] + r[2], r[1] + r[3]], [r[0], r[1] + r[3]]]; }
    function bbox(pts) {
      var b = [Infinity, Infinity, -Infinity, -Infinity];
      for (var i = 0; i < pts.length; i++) {
        if (pts[i][0] < b[0]) b[0] = pts[i][0]; if (pts[i][1] < b[1]) b[1] = pts[i][1];
        if (pts[i][0] > b[2]) b[2] = pts[i][0]; if (pts[i][1] > b[3]) b[3] = pts[i][1];
      }
      return b;
    }
    function inPoly(p, poly) {
      var inside = false;
      for (var i = 0, j = poly.length - 1; i < poly.length; j = i++) {
        var xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
        if (((yi > p[1]) !== (yj > p[1])) && (p[0] < (xj - xi) * (p[1] - yi) / (yj - yi) + xi)) inside = !inside;
      }
      return inside;
    }
    function centroid(poly) {
      var a = 0, cx = 0, cy = 0;
      for (var i = 0, j = poly.length - 1; i < poly.length; j = i++) {
        var f = poly[j][0] * poly[i][1] - poly[i][0] * poly[j][1];
        a += f; cx += (poly[j][0] + poly[i][0]) * f; cy += (poly[j][1] + poly[i][1]) * f;
      }
      var bb = bbox(poly), c = [(bb[0] + bb[2]) / 2, (bb[1] + bb[3]) / 2];
      if (Math.abs(a) < 1e-6) return c;
      var g = [cx / (3 * a), cy / (3 * a)];
      return inPoly(g, poly) ? g : c;
    }
    // first intersection of ray p + t*dir (t>0) with polygon edges
    function rayHit(p, dir, poly) {
      var best = Infinity;
      for (var i = 0, j = poly.length - 1; i < poly.length; j = i++) {
        var a = poly[j], e = sub(poly[i], a), den = cross(dir, e);
        if (Math.abs(den) < 1e-9) continue;
        var w = sub(a, p), t = cross(w, e) / den, u = cross(w, dir) / den;
        if (t > 1e-6 && u >= 0 && u <= 1 && t < best) best = t;
      }
      return best === Infinity ? null : best;
    }
    // Douglas-Peucker; returns kept indices
    function simplify(pts, tol) {
      var keep = {}; keep[0] = 1; keep[pts.length - 1] = 1;
      (function rec(i0, i1) {
        var md = 0, mi = -1;
        for (var i = i0 + 1; i < i1; i++) { var d = segProject(pts[i], pts[i0], pts[i1]).d; if (d > md) { md = d; mi = i; } }
        if (mi >= 0 && md > tol) { keep[mi] = 1; rec(i0, mi); rec(mi, i1); }
      })(0, pts.length - 1);
      var out = [];
      for (var k = 0; k < pts.length; k++) if (keep[k]) out.push(k);
      return out;
    }
  
    /* ------------------------------------------------------------------ text */
    function lc(s) { return String(s == null ? '' : s).toLowerCase(); }
    function cap(s) { s = String(s || ''); return s.charAt(0).toUpperCase() + s.slice(1); }
    function slug(s) { return lc(s).replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''); }
    var ORD = ['zeroth', 'first', 'second', 'third', 'fourth', 'fifth'];
    function ordFloor(level) {
      var n = parseInt(level, 10);
      if (isNaN(n)) return 'Level ' + level;
      var s = (n % 100 >= 11 && n % 100 <= 13) ? 'th' : ({ 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th');
      return n + s + ' floor';
    }
    function joinAnd(a) { return a.length < 2 ? (a[0] || '') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1]; }
    function theB(code) { var n = B[code] ? B[code].name : code; return /^the\s/i.test(n) ? n : 'the ' + n; }
    var THE_WORDS = /\b(lobby|atrium|bookstore|library|cafeteria|lounge|desks?|kiosks?|commons|court|hall|restrooms?|stairs?|elevators?|gym|theater|theatre|plaza|patio|courtyard|food court|study rooms?)$/i;
    function withThe(name) { return /^the\s/i.test(name) || !THE_WORDS.test(name) ? name : 'the ' + name; }
    // "Career Center 105", "the Bookstore (120)", "Room 215", "the restrooms"
    // "Grand stair (welcome lobby, east end)" -> "Grand stair"; "Atrium 3 - carpeted lounge" -> "Atrium 3"
    function speak(s) {
      s = String(s || '').replace(/\([^)]*\)?/g, ' ').replace(/\[[^\]]*\]?/g, ' ');
      s = s.split(/\s+[-\u2013\u2014\/]\s+|;/)[0];
      return s.replace(/\s+/g, ' ').replace(/[\s,.:]+$/, '').trim();
    }
    function shortPlace(s) {
      s = speak(s).split(/\s+(?:by|near|next to|beside|off|facing|faces|across from|behind|between|at|in)\s+|,/i)[0];
      s = s.replace(/\bvestibule\b(\s+[\w-]*\d[\w-]*)?/ig, ' ').replace(/\s+[\w-]*\d[\w-]*$/, '');
      return s.replace(/\s+/g, ' ').trim();
    }
    function hasNum(r) { return !!r.num && /\d/.test(r.num); }
    function roomRef(r) {
      var nm = r.say;
      if (r.kind === 'restroom' && (!nm || /rest ?rooms?|bathrooms?|r\/r/i.test(nm))) {
        if (/^(men|women|ladies|family)/i.test(nm)) return 'the ' + nm.replace(/\bmens\b/i, 'men\u2019s').replace(/\bwomens\b/i, 'women\u2019s').replace(/'/g, '\u2019').toLowerCase();
        return 'the restrooms';
      }
      if (!nm) return hasNum(r) ? 'Room ' + r.num : 'the room';
      if (!hasNum(r) || nm.indexOf(r.num) >= 0) return withThe(nm);
      var n = withThe(nm);
      return n === nm ? nm + ' ' + r.num : n + ' (' + r.num + ')';
    }
    function roomTitle(r) { return r.say ? r.say + (hasNum(r) && r.say.indexOf(r.num) < 0 ? ' (' + r.num + ')' : '') : (hasNum(r) ? 'Room ' + r.num : cap(r.kind)); }
    function levelLabel(b, level) { var f = FLOORS[b + '|' + level]; return f ? f.label : 'Level ' + level; }
  
    /* ------------------------------------------------------------------- load */
    function mpu(code) { return (B[code] && B[code].mpu) || CFG.metersPerUnit; }
    function addNode(gid, o) { N[gid] = o; ADJ[gid] = ADJ[gid] || []; }
    function addEdge(a, b, w, type, ref) {
      if (!N[a] || !N[b] || a === b) return;
      ADJ[a].push({ to: b, w: w, type: type, ref: ref });
      ADJ[b].push({ to: a, w: w, type: type, ref: ref });
    }
    function xy(g) { return [N[g].x, N[g].y]; }
    function addTarget(t) { TARGETS[t.id] = t; TKEY[lc(t.id)] = t.id; }
  
    function addBuilding(bj) {
      var code = String(bj.building || bj.code || '').toUpperCase();
      if (!code) return;
      var b = {
        code: code, name: bj.name || code, aliases: (bj.aliases || []).slice(), north: bj.north || 0,
        floors: [], entrances: [], verticals: [],
        mpu: bj.metersPerUnit || (bj.metersPer1000 ? bj.metersPer1000 / 1000 : null)
      };
      B[code] = b; BLIST.push(b);
      var floors = bj.floors || [], i, j;
      for (i = 0; i < floors.length; i++) {
        var f = floors[i], fk = code + '|' + f.level;
        var fr = {
          key: fk, b: code, level: f.level, label: f.label || ('Level ' + f.level),
          width: f.width || 1000, height: f.height || 600, outline: f.outline || null,
          rooms: [], edges: [], labels: f.labels || [], verts: [], ents: [], nodes: []
        };
        FLOORS[fk] = fr; b.floors.push(fr);
        var nodes = f.nodes || [];
        for (j = 0; j < nodes.length; j++) {
          var nd = nodes[j], gid = code + ':' + nd.id;
          addNode(gid, { gid: gid, id: nd.id, b: code, level: f.level, fk: fk, x: +nd.x, y: +nd.y, kind: nd.kind || 'hall' });
          fr.nodes.push(gid);
        }
      }
      // edges after all nodes exist (a floor may reference ids defined later)
      for (i = 0; i < floors.length; i++) {
        var f2 = floors[i], fr2 = FLOORS[code + '|' + f2.level], es = f2.edges || [];
        for (j = 0; j < es.length; j++) {
          var a = code + ':' + es[j][0], c = code + ':' + es[j][1];
          if (!N[a] || !N[c]) continue;
          addEdge(a, c, dist(xy(a), xy(c)) * mpu(code), 'walk');
          fr2.edges.push([a, c]);
        }
        var rooms = f2.rooms || [];
        for (j = 0; j < rooms.length; j++) addRoom(code, fr2, rooms[j]);
        for (j = 0; j < fr2.labels.length; j++) {
          var lb = fr2.labels[j], ng = nearestNode(fr2.key, [lb.x, lb.y]);
          if (!ng) continue;
          addTarget({ id: code + '-label-' + slug(lb.text), kind: 'label', b: code, level: f2.level, label: speak(lb.text) || lb.text, name: lb.text, say: speak(lb.text), gids: [ng], pt: [lb.x, lb.y] });
        }
      }
      var vs = bj.vertical || [];
      for (i = 0; i < vs.length; i++) {
        var v = vs[i], kind = v.kind === 'elevator' ? 'elevator' : 'stair';
        var vr = { id: v.id, kind: kind, name: v.name || '', b: code, nodes: {} };
        b.verticals.push(vr);
        var lv = [];
        for (var key in v.nodes) if (v.nodes.hasOwnProperty(key)) {
          var vg = code + ':' + v.nodes[key];
          if (!N[vg]) continue;
          vr.nodes[key] = vg; N[vg].vert = vr; lv.push({ level: +key, g: vg });
          if (FLOORS[N[vg].fk]) FLOORS[N[vg].fk].verts.push(vg);
        }
        lv.sort(function (p, q) { return p.level - q.level; });
        for (j = 1; j < lv.length; j++) {
          var per = kind === 'elevator' ? CFG.elevatorMeters : CFG.stairMeters;
          addEdge(lv[j - 1].g, lv[j].g, per * Math.max(1, Math.abs(lv[j].level - lv[j - 1].level)), kind, vr);
        }
      }
      var en = bj.entrances || [];
      for (i = 0; i < en.length; i++) {
        var e = en[i], eg = code + ':' + e.node;
        if (!N[eg]) continue;
        var er = { id: e.id || (code + '-ent-' + i), b: code, level: N[eg].level, gid: eg, side: e.side || '', name: e.name || '' };
        ENTR[er.id] = er; b.entrances.push(er); N[eg].ent = er;
        FLOORS[N[eg].fk].ents.push(eg);
        addTarget({ id: er.id, kind: 'entrance', b: code, level: er.level, label: er.name ? cap(shortPlace(er.name)) : b.name + ' entrance', name: er.name, gids: [eg], ent: er });
      }
      addTarget({ id: code, kind: 'building', b: code, level: b.entrances.length ? b.entrances[0].level : (b.floors[0] && b.floors[0].level), label: b.name, name: b.name, gids: null });
      if (bj.desk && bj.desk.node && N[code + ':' + bj.desk.node]) {
        DESK = { gid: code + ':' + bj.desk.node, facing: bj.desk.facing };
        DEFAULT_B = code;
      }
    }
  
    function addRoom(code, fr, rm) {
      var num = String(rm.num == null ? '' : rm.num);
      var poly = rm.poly || (rm.rect ? rectPoly(rm.rect) : null);
      var r = {
        id: rm.id || (code + '-' + num), num: num, name: rm.name || '', say: speak(rm.name), kind: rm.kind || 'other',
        poly: poly, rect: rm.rect || null, b: code, level: fr.level, fk: fr.key, door: null
      };
      if (poly && poly.length >= 3) { r.bb = bbox(poly); r.c = centroid(poly); }
      if (rm.door && N[code + ':' + rm.door]) {
        r.door = code + ':' + rm.door;
        (DOORS[r.door] = DOORS[r.door] || []).push(r);
      }
      fr.rooms.push(r);
      ROOMS[r.id] = r;
      if (num) {
        ROOMIDX[code + '|' + lc(num)] = r;
        var tail = /^\d+-(\w+)$/.exec(num);
        if (tail && !ROOMIDX[code + '|' + lc(tail[1])]) ROOMIDX[code + '|' + lc(tail[1])] = r;
      }
      if (r.door) addTarget({ id: r.id, kind: 'room', b: code, level: fr.level, label: roomTitle(r), name: r.name, say: r.say, num: hasNum(r) ? num : '', gids: [r.door], room: r });
    }
  
    function nearestNode(fk, p, kinds) {
      var fr = FLOORS[fk], best = null, bd = Infinity;
      if (!fr) return null;
      for (var i = 0; i < fr.nodes.length; i++) {
        var n = N[fr.nodes[i]];
        if (!n || (kinds && !kinds[n.kind])) continue;
        var d = dist(p, [n.x, n.y]);
        if (d < bd) { bd = d; best = n.gid; }
      }
      return best;
    }
  
    function load(data) {
      reset();
      data = data || {};
      if (data.config) config(data.config);
      if (data.metersPerUnit) CFG.metersPerUnit = data.metersPerUnit;
      var bs = data.buildings || [];
      for (var i = 0; i < bs.length; i++) if (bs[i]) addBuilding(bs[i]);
      if (!DEFAULT_B && BLIST.length) DEFAULT_B = B.CC ? 'CC' : BLIST[0].code;
      if (!DESK && DEFAULT_B && B[DEFAULT_B].entrances.length) DESK = { gid: B[DEFAULT_B].entrances[0].gid };
      var campus = data.campus || {};
      CAMPUS.layout = campus.buildingsLayout || null;
      var links = campus.links || [];
      for (i = 0; i < links.length; i++) {
        var L = links[i], a = endpointGid(L.from), c = endpointGid(L.to);
        if (!a || !c) continue;
        var lk = { from: a, to: c, say: L.say || '', meters: +L.meters || CFG.outdoorMeters };
        CAMPUS.links.push(lk);
        addEdge(a, c, lk.meters, 'outdoor', lk);
      }
      return { buildings: BLIST.length, nodes: Object.keys(N).length, rooms: Object.keys(ROOMS).length, links: CAMPUS.links.length };
    }
    function endpointGid(id) {
      if (!id) return null;
      if (ENTR[id]) return ENTR[id].gid;
      if (N[id]) return id;
      if (ROOMS[id] && ROOMS[id].door) return ROOMS[id].door;
      return null;
    }
    function config(o) { for (var k in o) if (o.hasOwnProperty(k)) CFG[k] = o[k]; return CFG; }
  
    /* ------------------------------------------------------------------- desk */
    // nearest point on a walkable hallway segment of that floor
    function snap(building, level, x, y) {
      var fr = FLOORS[building + '|' + level];
      if (!fr) return null;
      var p = [x, y], best = null;
      for (var i = 0; i < fr.edges.length; i++) {
        var a = fr.edges[i][0], c = fr.edges[i][1];
        if (N[a].kind === 'desk' || N[c].kind === 'desk') continue;
        var q = segProject(p, xy(a), xy(c));
        if (!best || q.d < best.d) best = { d: q.d, x: q.x, y: q.y, a: a, b: c, t: q.t };
      }
      if (!best) { var g = nearestNode(fr.key, p); return g ? { x: N[g].x, y: N[g].y, a: g, b: g, t: 0, node: g } : null; }
      var nn = best.t < 0.5 ? best.a : best.b;
      best.node = dist([best.x, best.y], xy(nn)) * mpu(building) < 1.5 ? nn : null;
      best.building = building; best.floor = level;
      return best;
    }
    function removeNode(g) {
      if (!N[g]) return;
      var es = ADJ[g] || [];
      for (var i = 0; i < es.length; i++) {
        var back = ADJ[es[i].to] || [];
        for (var j = back.length - 1; j >= 0; j--) if (back[j].to === g) back.splice(j, 1);
      }
      delete ADJ[g]; delete N[g];
    }
    function setDesk(x) {
      DIST = null;
      if (x == null) return getDesk();
      if (typeof x === 'string') {
        var g = N[x] ? x : (DEFAULT_B && N[DEFAULT_B + ':' + x] ? DEFAULT_B + ':' + x : endpointGid(x));
        if (g) DESK = { gid: g, facing: DESK && DESK.facing };
        return getDesk();
      }
      var bcode = String(x.building || (DESK && N[DESK.gid] && N[DESK.gid].b) || DEFAULT_B || '').toUpperCase();
      var level = x.floor != null ? x.floor : (x.level != null ? x.level : (DESK && N[DESK.gid] ? N[DESK.gid].level : 1));
      if (x.node && N[bcode + ':' + x.node]) { DESK = { gid: bcode + ':' + x.node, facing: x.facing != null ? x.facing : DESK && DESK.facing }; return getDesk(); }
      var s = snap(bcode, level, +x.x, +x.y);
      if (!s) return getDesk();
      var facing = x.facing != null ? x.facing : (DESK && DESK.facing);
      removeNode(bcode + ':__desk');
      if (s.node) { DESK = { gid: s.node, facing: facing }; return getDesk(); }
      var vg = bcode + ':__desk';
      addNode(vg, { gid: vg, id: '__desk', b: bcode, level: level, fk: bcode + '|' + level, x: s.x, y: s.y, kind: 'desk', virtual: true });
      addEdge(vg, s.a, dist([s.x, s.y], xy(s.a)) * mpu(bcode), 'walk');
      addEdge(vg, s.b, dist([s.x, s.y], xy(s.b)) * mpu(bcode), 'walk');
      DESK = { gid: vg, facing: facing };
      return getDesk();
    }
    function getDesk() {
      if (!DESK || !N[DESK.gid]) return null;
      var n = N[DESK.gid];
      return { building: n.b, floor: n.level, x: n.x, y: n.y, node: n.virtual ? null : n.id, facing: DESK.facing };
    }
  
    /* -------------------------------------------------------------- dijkstra */
    function hpush(h, it) {
      h.push(it); var i = h.length - 1;
      while (i > 0) { var p = (i - 1) >> 1; if (h[p][0] <= h[i][0]) break; var t = h[p]; h[p] = h[i]; h[i] = t; i = p; }
    }
    function hpop(h) {
      var top = h[0], last = h.pop();
      if (h.length) {
        h[0] = last; var i = 0;
        for (;;) {
          var l = 2 * i + 1, r = l + 1, m = i;
          if (l < h.length && h[l][0] < h[m][0]) m = l;
          if (r < h.length && h[r][0] < h[m][0]) m = r;
          if (m === i) break;
          var t = h[m]; h[m] = h[i]; h[i] = t; i = m;
        }
      }
      return top;
    }
    function dijkstra(src, targets, avoidStairs) {
      var D = {}, P = {}, done = {}, heap = [[0, src]];
      D[src] = 0;
      while (heap.length) {
        var u = hpop(heap)[1];
        if (done[u]) continue;
        done[u] = 1;
        if (targets && targets[u]) return { dist: D, prev: P, hit: u };
        var es = ADJ[u] || [];
        for (var i = 0; i < es.length; i++) {
          var e = es[i];
          if (avoidStairs && e.type === 'stair') continue;
          var nd = D[u] + e.w;
          if (D[e.to] === undefined || nd < D[e.to]) { D[e.to] = nd; P[e.to] = { from: u, e: e }; hpush(heap, [nd, e.to]); }
        }
      }
      return { dist: D, prev: P, hit: null };
    }
    function deskDist() {
      if (!DIST && DESK && N[DESK.gid]) DIST = dijkstra(DESK.gid, null, false).dist;
      return DIST || {};
    }
  
    /* ------------------------------------------------------------------- find */
    var DEFAULT_ALIASES = {
      CC: ['cc', 'wcc', 'campus commons', 'the commons', 'commons', 'commons building'],
      SC: ['sc', 'wsc', 'student center', 'student centre', 'student union', 'student center building'],
      L: ['l', 'lib', 'wl', 'library', 'the library', 'library building']
    };
    var ONES = { zero: 0, one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9 };
    var TEENS = { ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14, fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19 };
    var TENS = { twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60, seventy: 70, eighty: 80, ninety: 90 };
    var STOP = {};
    ('where wheres is are the a an to get go going how do does i im find looking look for of in at on way can could you tell me ' +
      'please need want which what located location room rm building there its it we my thanks thank hi hello directions direction ' +
      'toward towards near by from here and or um uh like some show take be will would whats that this number located ok okay so just ' +
      'hey sir maam miss walk head am').split(' ').forEach(function (w) { STOP[w] = 1; });
    var GENERIC = {};
    ('office offices center centre desk desks area lobby hall lab labs services service station counter front main student students ' +
      'room rooms suite space').split(' ').forEach(function (w) { GENERIC[w] = 1; });
    var KIND_WORDS = [
      { re: /\b(rest ?rooms?|bath ?rooms?|toilets?|men'?s room|women'?s room|ladies room|washrooms?)\b/, kind: 'restroom', label: 'Restrooms' },
      { re: /\b(elevators?|lifts?)\b/, kind: 'elevator', label: 'Elevator' },
      { re: /\b(stairs?|stairways?|stairwells?)\b/, kind: 'stair', label: 'Stairs' }
    ];
  
    function aliasTable() {
      var out = [], seen = {};
      function add(code, a) {
        var t = lc(a).replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
        if (!t || seen[code + '|' + t]) return;
        seen[code + '|' + t] = 1;
        out.push({ code: code, toks: t.split(' ') });
      }
      var codes = BLIST.length ? BLIST.map(function (b) { return b.code; }) : Object.keys(DEFAULT_ALIASES);
      codes.forEach(function (code) {
        (DEFAULT_ALIASES[code] || []).forEach(function (a) { add(code, a); });
        add(code, code);
        if (B[code]) { add(code, B[code].name); B[code].aliases.forEach(function (a) { add(code, a); }); }
      });
      out.sort(function (p, q) { return q.toks.length - p.toks.length; });
      return out;
    }
  
    function tokenize(text) {
      var s = lc(text).replace(/[’']s\b/g, '').replace(/[’']/g, '');
      s = s.replace(/[^a-z0-9\s-]+/g, ' ');
      s = s.replace(/([a-z])-/g, '$1 ').replace(/-([a-z])/g, ' $1').replace(/([a-z])(\d)/g, '$1 $2');
      var raw = s.split(/\s+/), toks = [];
      for (var i = 0; i < raw.length; i++) { var t = raw[i].replace(/^-+|-+$/g, ''); if (t) toks.push(t); }
      return toks;
    }
    function wordsToDigits(toks) {
      var out = [], hundred = -1;
      function isNum(t) { return /^\d+$/.test(t); }
      for (var i = 0; i < toks.length; i++) {
        var t = toks[i], nx = toks[i + 1], last = out[out.length - 1], val = null;
        if (t === 'oh' || t === 'o') { if (last && isNum(last) && hundred < 0) { out.push('0'); continue; } out.push(t); continue; }
        if (t === 'and' && hundred >= 0) continue;
        if (t === 'hundred' && last && /^\d$/.test(last)) { out[out.length - 1] = last + '00'; hundred = out.length - 1; continue; }
        if (ONES.hasOwnProperty(t)) val = ONES[t];
        else if (TEENS.hasOwnProperty(t)) val = TEENS[t];
        else if (TENS.hasOwnProperty(t)) { val = TENS[t]; if (nx && ONES.hasOwnProperty(nx) && ONES[nx] > 0) { val += ONES[nx]; i++; } }
        if (val === null) { hundred = -1; out.push(t); continue; }
        if (hundred >= 0 && val < 100) { out[hundred] = String(parseInt(out[hundred], 10) + val); hundred = -1; continue; }
        hundred = -1;
        out.push(String(val));
      }
      return out;
    }
    // normalise free text into tokens: spelled codes joined ("w c c" -> "wcc"), number words -> digits, "2 15" -> "215", "331 b" -> "331b"
    function normTokens(text, aliases) {
      var toks = wordsToDigits(tokenize(text));
      var short = {};
      aliases.forEach(function (a) { if (a.toks.length === 1 && a.toks[0].length <= 4) short[a.toks[0]] = 1; });
      var out = [], i, j;
      for (i = 0; i < toks.length; i++) {
        if (/^[a-z]$/.test(toks[i])) {
          var done = false;
          for (var k = 3; k >= 2 && !done; k--) {
            var seq = toks.slice(i, i + k);
            if (seq.length === k && seq.every(function (x) { return /^[a-z]$/.test(x); }) && short[seq.join('')]) { out.push(seq.join('')); i += k - 1; done = true; }
          }
          if (done) continue;
        }
        out.push(toks[i]);
      }
      toks = out; out = [];
      for (i = 0; i < toks.length; i++) {
        if (/^\d+$/.test(toks[i]) && !/^(level|floor|lvl)$/.test(toks[i - 1] || '')) {
          var acc = toks[i];
          for (j = i + 1; j < toks.length && /^\d+$/.test(toks[j]) && (acc + toks[j]).length <= 4 && acc.length < 3; j++) acc += toks[j];
          i = j - 1;
          var nx = toks[i + 1];
          if (nx && /^[a-h]$/.test(nx) && (i + 2 >= toks.length || STOP[toks[i + 2]])) { acc += nx; i++; }
          out.push(acc);
          continue;
        }
        out.push(toks[i]);
      }
      return out;
    }
    // { building, num, tokens, spans } — pure text parsing (works without data)
    function parseQuery(text) {
      var aliases = aliasTable(), toks = normTokens(text, aliases), spans = [], i, a;
      for (i = 0; i < toks.length; i++) {
        for (a = 0; a < aliases.length; a++) {
          var al = aliases[a].toks, ok = true;
          for (var k = 0; k < al.length; k++) if (toks[i + k] !== al[k]) { ok = false; break; }
          if (!ok) continue;
          var end = i + al.length - 1, nextTok = toks[end + 1] || '';
          if (al.length === 1 && al[0].length === 1 && !/^\d/.test(nextTok)) continue;   // "l" only as "L 217"
          spans.push({ code: aliases[a].code, i0: i, i1: end });
          i = end; break;
        }
      }
      var num = null, numIdx = -1, building = null;
      for (i = 0; i < toks.length; i++) {
        var t = toks[i];
        if (!/^\d{1,4}(-\d{1,4})?[a-z]?$/.test(t)) continue;
        var prev = toks[i - 1] || '', strong = /^(room|rm|suite|number)$/.test(prev), adj = null;
        for (a = 0; a < spans.length; a++) if (spans[a].i1 === i - 1 || (spans[a].i1 === i - 2 && /^(room|rm)$/.test(prev))) adj = spans[a].code;
        if (!(adj || strong || /^\d{3,4}/.test(t) || /-/.test(t) || /[a-z]$/.test(t))) continue;
        num = t; numIdx = i; building = adj;
        break;
      }
      if (!building && spans.length) building = spans[0].code;
      return { building: building, num: num, numIdx: numIdx, tokens: toks, spans: spans };
    }
  
    function stem(w) { return w.length > 4 ? w.replace(/(ies)$/, 'y').replace(/(es|s)$/, '') : w; }
    function lev1(a, b) {          // edit distance <= 1 ?
      if (Math.abs(a.length - b.length) > 1) return false;
      var i = 0, j = 0, e = 0;
      while (i < a.length && j < b.length) {
        if (a[i] === b[j]) { i++; j++; continue; }
        if (++e > 1) return false;
        if (a.length > b.length) i++; else if (b.length > a.length) j++; else { i++; j++; }
      }
      return e + (a.length - i) + (b.length - j) <= 1;
    }
    function wordEq(a, b) {
      if (a === b) return true;
      var sa = stem(a), sb = stem(b);
      if (sa === sb) return true;
      if (sa.length >= 5 && sb.length >= 5 && lev1(sa, sb)) return true;
      return false;
    }
    function nameScore(name, qtoks, qjoined) {
      var nt = tokenize(name).filter(function (w) { return !STOP[w] && !/^\d+$/.test(w); });
      if (!nt.length) return 0;
      var joined = nt.join('');
      if (joined.length >= 5 && qjoined.indexOf(joined) >= 0) return 1.05;
      var dTot = 0, dHit = 0, gTot = 0, gHit = 0;
      for (var i = 0; i < nt.length; i++) {
        var hit = false;
        for (var j = 0; j < qtoks.length; j++) if (wordEq(nt[i], qtoks[j])) { hit = true; break; }
        if (GENERIC[nt[i]]) { gTot++; if (hit) gHit++; } else { dTot++; if (hit) dHit++; }
      }
      if (dTot === 0) return gHit === gTot ? 0.8 : 0;
      if (dHit === 0) return 0;
      return dHit / dTot + (gTot ? 0.1 * gHit / gTot : 0.05);
    }
    function result(t) {
      if (!t) return null;
      return { id: t.id, building: t.b, floor: t.level, label: t.label, kind: t.kind, name: t.say != null ? t.say : (t.name || ''), num: t.num || '' };
    }
    function nearestOf(cands) {
      if (!cands.length) return null;
      var D = deskDist(), best = null, bd = Infinity;
      for (var i = 0; i < cands.length; i++) {
        var t = cands[i], g = t.gids && t.gids[0], d = g != null && D[g] != null ? D[g] : 1e9;
        if (best === null || d < bd) { best = t; bd = d; }
      }
      return best;
    }
  
    function find(text) {
      if (!text || !BLIST.length) return null;
      var q = parseQuery(text), toks = q.tokens, ql = toks.join(' ');
      // 1) room number
      if (q.num) {
        var num = q.num, hit = null;
        var tailN = /^\d+-(\w+)$/.exec(num);
        if (q.building) hit = ROOMIDX[q.building + '|' + num] || (tailN && ROOMIDX[q.building + '|' + tailN[1]]);
        else {
          hit = DEFAULT_B && ROOMIDX[DEFAULT_B + '|' + num];
          if (!hit) {
            var others = BLIST.map(function (b) { return ROOMIDX[b.code + '|' + num]; }).filter(Boolean);
            if (others.length === 1) hit = others[0];
          }
        }
        if (hit && TARGETS[hit.id]) return result(TARGETS[hit.id]);
      }
      // 2) facility kinds: nearest restroom / elevator / stairs
      var restrictB = q.building;
      for (var k = 0; k < KIND_WORDS.length; k++) {
        if (!KIND_WORDS[k].re.test(ql)) continue;
        var kind = KIND_WORDS[k].kind, cands = [];
        if (kind === 'restroom') {
          for (var id in TARGETS) if (TARGETS[id].kind === 'room' && TARGETS[id].room.kind === 'restroom' && (!restrictB || TARGETS[id].b === restrictB)) cands.push(TARGETS[id]);
        } else {
          for (var g in N) if (N[g].kind === kind && N[g].vert && (!restrictB || N[g].b === restrictB))
            cands.push({ id: g, kind: 'node', b: N[g].b, level: N[g].level, label: cap(N[g].vert.name || KIND_WORDS[k].label), gids: [g] });
        }
        var near = nearestOf(cands);
        if (near) return result(near);
      }
      // 3) names (rooms, area labels, entrances), building alias words removed
      var used = {};
      q.spans.forEach(function (s) { for (var i = s.i0; i <= s.i1; i++) used[i] = 1; });
      var rest = toks.filter(function (w, i) { return !used[i] && !STOP[w] && !/^\d/.test(w); });
      if (rest.length) {
        var qj = rest.join(''), scored = [];
        for (var tid in TARGETS) {
          var t = TARGETS[tid];
          if (t.kind === 'building' || !t.name) continue;
          var s = nameScore(t.name, rest, qj);
          if (s >= 0.5) scored.push({ t: t, s: s + (restrictB && t.b === restrictB ? 0.3 : 0) + (t.kind === 'room' ? 0.02 : 0) });
        }
        if (q.num) scored = scored.filter(function (x) { return x.s >= 0.85; });
        if (scored.length) {
          scored.sort(function (a, b) { return b.s - a.s; });
          var top = scored.filter(function (x) { return x.s >= scored[0].s - 1e-9; }).map(function (x) { return x.t; });
          return result(top.length > 1 ? nearestOf(top) : top[0]);
        }
      }
      // 4) just a building ("the student center")
      if (q.building && !q.num && TARGETS[q.building]) return result(TARGETS[q.building]);
      return null;
    }
  
    /* ------------------------------------------------------------------ route */
    function resolveTarget(to, srcG) {
      var id = to && typeof to === 'object' ? to.id : to;
      if (id == null) return null;
      id = String(id);
      var t = TARGETS[id] || TARGETS[TKEY[lc(id)]];
      if (!t && N[id]) {
        var n = N[id];
        t = { id: id, kind: 'node', b: n.b, level: n.level, label: n.vert ? cap(n.vert.name || n.kind) : (n.ent ? cap(n.ent.name) : 'Here'), gids: [id] };
      }
      if (!t) { var f = find(id); if (f) t = TARGETS[f.id] || resolveTarget(f.id); }
      if (!t) return null;
      if (t.kind === 'building') {
        var b = B[t.b], gids = b.entrances.map(function (e) { return e.gid; });
        if (srcG && N[srcG] && N[srcG].b === t.b) {
          var main = b.entrances.filter(function (e) { return /main|front|lobby/i.test(e.name); })[0] || b.entrances[0];
          gids = main ? [main.gid] : [];
        }
        if (!gids.length && b.floors.length) gids = b.floors[0].nodes.slice(0, 1);
        t = { id: t.id, kind: 'building', b: t.b, level: t.level, label: t.label, name: t.name, gids: gids };
      }
      return t;
    }
    function resolveSource(from) {
      if (from == null) return DESK && N[DESK.gid] ? { gid: DESK.gid, label: 'Front desk', desk: true, facing: DESK.facing } : null;
      if (typeof from === 'object' && from.x != null) {
        var bc = String(from.building || DEFAULT_B).toUpperCase(), lv = from.floor != null ? from.floor : 1;
        var g = nearestNode(bc + '|' + lv, [+from.x, +from.y]);
        return g ? { gid: g, label: 'Start' } : null;
      }
      var id = typeof from === 'object' ? from.id : String(from);
      if (N[id]) return { gid: id, label: N[id].kind === 'desk' ? 'Front desk' : 'Start', desk: N[id].kind === 'desk' };
      if (DEFAULT_B && N[DEFAULT_B + ':' + id]) return resolveSource(DEFAULT_B + ':' + id);
      var t = TARGETS[id] || TARGETS[TKEY[lc(id)]];
      if (t && t.gids && t.gids.length) return { gid: t.gids[0], label: t.label, room: t.room };
      return null;
    }
  
    function route(to, opts) {
      opts = opts || {};
      var src = resolveSource(opts.from);
      if (!src) return null;
      var tgt = resolveTarget(to, src.gid);
      if (!tgt || !tgt.gids || !tgt.gids.length) return null;
      var tset = {};
      tgt.gids.forEach(function (g) { tset[g] = 1; });
      var r = dijkstra(src.gid, tset, !!opts.avoidStairs);
      if (!r.hit) return null;
      var path = [], g = r.hit;
      while (g !== src.gid) { var p = r.prev[g]; path.unshift({ g: g, via: p.e }); g = p.from; }
      path.unshift({ g: src.gid, via: null });
      return build(path, src, tgt, r.dist[r.hit], opts);
    }
  
    function build(path, src, tgt, cost, opts) {
      var legs = [], cur = null, i;
      function open(g, kind, via) {
        cur = { kind: 'indoor', building: N[g].b, floor: N[g].level, fk: N[g].fk, nodes: [g], startKind: kind, startVia: via, endKind: null, endVia: null };
        legs.push(cur);
      }
      open(path[0].g, 'origin', null);
      for (i = 1; i < path.length; i++) {
        var g = path[i].g, via = path[i].via;
        if (via.type === 'outdoor') {
          cur.endKind = 'exit'; cur.endVia = via;
          legs.push({ kind: 'outdoor', building: 'campus', floor: null, from: path[i - 1].g, to: g, link: via.ref, meters: via.w });
          open(g, 'enter', via);
        } else if (via.type === 'stair' || via.type === 'elevator') {
          cur.endKind = 'vertical'; cur.endVia = via; cur.toFloor = N[g].level;
          open(g, 'vertical', via);
          cur.fromFloor = N[path[i - 1].g].level;
        } else cur.nodes.push(g);
      }
      cur.endKind = 'dest';
      // a floor you only pass through inside the stairwell is not a leg
      for (i = legs.length - 2; i > 0; i--) {
        var L = legs[i];
        if (L.kind === 'indoor' && L.nodes.length === 1 && L.startKind === 'vertical' && L.endKind === 'vertical') {
          legs[i - 1].toFloor = L.toFloor; legs[i + 1].fromFloor = legs[i - 1].floor;
          legs.splice(i, 1);
        }
      }
      var room = tgt.room || null;
      // points + labels
      for (i = 0; i < legs.length; i++) {
        var lg = legs[i];
        if (lg.kind === 'outdoor') {
          lg.points = campusPoints(lg.from, lg.to);
          lg.fromLabel = B[N[lg.from].b].name; lg.toLabel = B[N[lg.to].b].name;
          continue;
        }
        lg.points = lg.nodes.map(xy);
        if (lg.endKind === 'dest' && room && room.poly && room.door === lg.nodes[lg.nodes.length - 1]) {
          var dp = xy(room.door), dir = unit(sub(room.c, dp)), hitT = rayHit(dp, dir, room.poly);
          if (hitT != null && !inPoly(dp, room.poly)) {
            var inset = Math.min(10, dist(dp, room.c) * 0.25);
            lg.points.push([dp[0] + dir[0] * (hitT + inset), dp[1] + dir[1] * (hitT + inset)]);
          }
        }
        lg.label = (B[lg.building] ? B[lg.building].name : lg.building) + ' · ' + levelLabel(lg.building, lg.floor);
        lg.fromLabel = lg.startKind === 'origin' ? src.label : lg.startKind === 'vertical' ? cap(vertName(lg.startVia.ref)) : entName(N[lg.nodes[0]].ent);
        lg.toLabel = lg.endKind === 'dest' ? tgt.label : lg.endKind === 'vertical' ? cap(vertName(lg.endVia.ref)) + ' to ' + levelLabel(lg.building, lg.toFloor) : entName(N[lg.nodes[lg.nodes.length - 1]].ent);
      }
      var ctx = { src: src, tgt: tgt, room: room, used: {}, legs: legs };
      var around0 = roomAround(N[src.gid].fk, xy(src.gid));
      if (around0) ctx.used[around0.id] = 1;
      if (src.room) ctx.used[src.room.id] = 1;
      var steps = [];
      if (room && around0 === room && legs.length === 1) {
        steps.push({ icon: 'dest', text: 'You\u2019re already in ' + roomRef(room), leg: 0 });
        legs[0].kind = 'indoor';
      } else for (i = 0; i < legs.length; i++) {
        var st = legs[i].kind === 'outdoor' ? outdoorSteps(legs[i], ctx) : indoorSteps(legs[i], ctx, i === legs.length - 1);
        for (var s = 0; s < st.length; s++) { st[s].leg = i; steps.push(st[s]); }
      }
      var meters = Math.round(cost);
      var minutes = Math.max(1, Math.round(cost / CFG.walkMetersPerMin));
      var sN = N[src.gid], where;
      if (tgt.b !== sN.b) where = (B[tgt.b] ? B[tgt.b].name : tgt.b) + ', ' + ordFloor(tgt.level);
      else if (+tgt.level > +sN.level) where = 'Upstairs, ' + ordFloor(tgt.level);
      else if (+tgt.level < +sN.level) where = 'Downstairs, ' + ordFloor(tgt.level);
      else where = 'On this floor';
      var out = {
        to: { id: tgt.id, building: tgt.b, floor: tgt.level, label: tgt.label, kind: tgt.kind, name: tgt.say != null ? tgt.say : (tgt.name || ''), num: tgt.num || '' },
        from: { building: sN.b, floor: sN.level, x: sN.x, y: sN.y, label: src.label, desk: !!src.desk },
        legs: legs.map(publicLeg), steps: steps, meters: meters, minutes: minutes,
        summary: where + ' — about ' + minutes + ' min walk',
        avoidStairs: !!opts.avoidStairs
      };
      return out;
    }
    function publicLeg(l) {
      var o = { building: l.building, floor: l.floor, points: l.points, fromLabel: l.fromLabel, toLabel: l.toLabel, kind: l.kind };
      if (l.kind === 'outdoor') {
        o.fromBuilding = N[l.from].b; o.toBuilding = N[l.to].b; o.meters = Math.round(l.meters); o.say = l.link.say;
        o.fromPoint = xy(l.from); o.toPoint = xy(l.to); o.fromFloor = N[l.from].level; o.toFloor = N[l.to].level;
      } else {
        o.label = l.label; o.startKind = l.startKind; o.endKind = l.endKind; o.nodes = l.nodes.slice();
        if (l.endKind === 'vertical') { o.toFloor = l.toFloor; o.via = l.endVia.type; }
        if (l.startKind === 'vertical') { o.fromFloor = l.fromFloor; o.viaIn = l.startVia.type; }
      }
      return o;
    }
    function campusPoints(ga, gb) {
      var Lay = CAMPUS.layout;
      if (!Lay) return [];
      var a = layoutPoint(ga), b = layoutPoint(gb);
      return a && b ? [a, b] : [];
    }
    function layoutPoint(g) {
      var n = N[g], L = CAMPUS.layout && CAMPUS.layout[n.b], f = FLOORS[n.fk];
      if (!L || !f) return null;
      var ob = f.outline ? bbox(f.outline) : [0, 0, f.width, f.height];
      var u = (n.x - ob[0]) / ((ob[2] - ob[0]) || 1), v = (n.y - ob[1]) / ((ob[3] - ob[1]) || 1);
      u = Math.max(0, Math.min(1, u)); v = Math.max(0, Math.min(1, v));
      var p = [L.x + u * L.w, L.y + v * L.h], c = [L.x + L.w / 2, L.y + L.h / 2], a = (L.rot || 0) * Math.PI / 180;
      var d = sub(p, c);
      return [c[0] + d[0] * Math.cos(a) - d[1] * Math.sin(a), c[1] + d[0] * Math.sin(a) + d[1] * Math.cos(a)];
    }
  
    /* ------------------------------------------------------------ directions */
    function vertName(v) {
      if (!v) return 'the stairs';
      var n = lc(shortPlace(v.name)).trim();
      if (v.kind === 'elevator') return n ? 'the ' + n.replace(/^the\s+/, '').replace(/\belevator\b(?!s)/, 'elevator') : 'the elevator';
      if (!n) return 'the stairs';
      n = n.replace(/^the\s+/, '').replace(/\bstair(case|well|way)?$/, 'stairs');
      if (!/stair/.test(n)) n += ' stairs';
      return 'the ' + n;
    }
    function entName(e) {
      if (!e) return 'the doors';
      var n = shortPlace(e.name).replace(/^(North|South|East|West|Northeast|Northwest|Southeast|Southwest|Main|Front|Back|Side)\b/, function (w) { return w.toLowerCase(); });
      if (!n) return 'the ' + ({ N: 'north', S: 'south', E: 'east', W: 'west' }[e.side] || 'outside') + ' doors';
      n = n.replace(/^the\s+/i, '');
      if (!/door|entrance|exit|entry/i.test(n)) n += ' doors';
      return 'the ' + n;
    }
    function M(b, m) { return m / mpu(b); }   // meters -> canvas units
    // classify the junction at node g when arriving with heading h
    function junction(g, h, fk) {
      var es = ADJ[g] || [], deg = 0, straight = false;
      for (var i = 0; i < es.length; i++) {
        var e = es[i];
        if (e.type !== 'walk' || N[e.to].fk !== fk) continue;
        deg++;
        var dv = unit(sub(xy(e.to), xy(g)));
        if (Math.abs(angleBetween(h, dv)) < 30) straight = true;
      }
      if (straight) return 'cross';
      return deg <= 2 ? 'corner' : 'end';
    }
    // side branches passed on a run before turning that way: "the second hallway"
    function branchesPassed(leg, run, sign) {
      var c = 0;
      for (var j = run.i0 + 1; j < run.i1; j++) {
        var g = leg.nodes[j], es = ADJ[g] || [];
        for (var k = 0; k < es.length; k++) {
          var e = es[k], to = N[e.to];
          if (e.type !== 'walk' || to.fk !== leg.fk || to.kind !== 'hall') continue;
          if (e.to === leg.nodes[j - 1] || e.to === leg.nodes[j + 1]) continue;
          var walkDeg = (ADJ[e.to] || []).filter(function (x) { return x.type === 'walk'; }).length;
          if (walkDeg < 2) continue;
          var a = angleBetween(run.h, unit(sub(xy(e.to), xy(g))));
          if (Math.abs(a) > 45 && (a > 0) === (sign > 0)) { c++; break; }
        }
      }
      return c;
    }
    var SKIP_LM = { stair: 1, elevator: 1, mech: 1, storage: 1 };
    function lmScore(r) {
      if (SKIP_LM[r.kind]) return -1;
      if (r.say && !/^(collab\.?|classroom|office|storage|room|open|other)$/i.test(r.say)) return 3 + (r.kind === 'lobby' || r.kind === 'office' || r.kind === 'collab' ? 1 : 0);
      if (r.kind === 'restroom') return 2;
      return 0;
    }
    function runLandmarks(leg, run, ctx, max) {
      var c = [];
      for (var j = run.i0 + 1; j < run.i1; j++) {
        var rs = DOORS[leg.nodes[j]] || [];
        for (var k = 0; k < rs.length; k++) {
          var r = rs[k];
          if (r === ctx.room || ctx.used[r.id] || lmScore(r) < 2) continue;
          c.push({ r: r, s: lmScore(r) + j * 0.001 });
        }
      }
      c.sort(function (a, b) { return b.s - a.s; });
      var out = [], seen = {};
      for (var i = 0; i < c.length && out.length < max; i++) {
        var ref = roomRef(c[i].r);
        if (seen[ref]) continue;
        seen[ref] = 1; ctx.used[c[i].r.id] = 1; out.push({ r: c[i].r, ref: ref, j: c[i].s });
      }
      out.sort(function (a, b) { return (a.j % 1) - (b.j % 1); });
      return out.map(function (x) { return x.ref; });
    }
    function runArea(leg, run, ctx) {
      var fr = FLOORS[leg.fk], pts = leg.pts;
      for (var i = 0; i < fr.labels.length; i++) {
        var lb = fr.labels[i], key = 'label:' + lb.text, nm = speak(lb.text);
        if (ctx.used[key] || !nm || /\d/.test(nm) || /^(the )?(entrance|entry|open area|corridor|hall(way)?|vestibule|exit|area|space)$/i.test(nm)) continue;
        for (var j = run.i0; j < run.i1; j++) {
          if (segProject([lb.x, lb.y], pts[j], pts[j + 1]).d < M(leg.building, 12)) { ctx.used[key] = 1; return /^the /i.test(nm) ? nm : 'the ' + nm; }
        }
      }
      return null;
    }
    function roomAround(fk, p) {
      var fr = FLOORS[fk];
      for (var i = 0; i < fr.rooms.length; i++) { var r = fr.rooms[i]; if (r.poly && r.say && inPoly(p, r.poly)) return r; }
      return null;
    }
    function hallWord(leg, run) {
      var fr = FLOORS[leg.fk];
      if (run.len < M(leg.building, 6)) return 'a few steps';
      if (run.len >= fr.width * 0.4) return 'straight down the main hallway';
      return 'down the hallway';
    }
    function sideWord(deg) { return deg > 0 ? 'right' : 'left'; }
    function turnIcon(deg) {
      var a = Math.abs(deg);
      if (a >= 150) return 'uturn';
      if (a < 55) return deg > 0 ? 'slight-right' : 'slight-left';
      return deg > 0 ? 'right' : 'left';
    }
  
    function indoorSteps(leg, ctx, isLast) {
      var steps = [], b = leg.building, fr = FLOORS[leg.fk];
      var prefix = '';
      function push(icon, text) {
        if (prefix) { text = prefix + (/^(Walk|Turn|Take|Head|Go|Bear|Follow|Step|Come|The)\b/.test(text) ? text.charAt(0).toLowerCase() + text.slice(1) : text); prefix = ''; }
        steps.push({ icon: icon, text: cap(text) });
      }
      var pts = leg.pts = leg.nodes.map(xy);
      var keep = pts.length >= 2 ? simplify(pts, M(b, 1.8)) : [0];
      for (var changed = true; changed;) {
        changed = false;
        for (var k = 1; k < keep.length - 1; k++) {
          if (Math.abs(turnDeg(pts[keep[k - 1]], pts[keep[k]], pts[keep[k + 1]])) < 28) { keep.splice(k, 1); changed = true; break; }
        }
      }
      // short zig-zags in the hallway graph are not real turns
      for (changed = true; changed;) {
        changed = false;
        for (k = 1; k + 2 < keep.length; k++) {
          var ta = turnDeg(pts[keep[k - 1]], pts[keep[k]], pts[keep[k + 1]]), tb = turnDeg(pts[keep[k]], pts[keep[k + 1]], pts[keep[k + 2]]);
          var jogMax = Math.abs(ta) < 60 && Math.abs(tb) < 60 && (ta > 0) !== (tb > 0) ? 10 : 4;
          if (dist(pts[keep[k]], pts[keep[k + 1]]) >= M(b, jogMax)) continue;
          if ((ta > 0) !== (tb > 0)) keep.splice(k, 2); else keep.splice(k + 1, 1);
          changed = true; break;
        }
        for (k = 1; k < keep.length - 1 && !changed; k++) {
          if (Math.abs(turnDeg(pts[keep[k - 1]], pts[keep[k]], pts[keep[k + 1]])) < 28) { keep.splice(k, 1); changed = true; }
        }
      }
      var runs = [], turns = [null];
      for (k = 0; k + 1 < keep.length; k++) {
        var L = 0;
        for (var j = keep[k]; j < keep[k + 1]; j++) L += dist(pts[j], pts[j + 1]);
        runs.push({ i0: keep[k], i1: keep[k + 1], len: L, h: unit(sub(pts[keep[k + 1]], pts[keep[k]])) });
        if (k > 0) turns.push(turnDeg(pts[keep[k - 1]], pts[keep[k]], pts[keep[k + 1]]));
      }
      var n = runs.length, endG = leg.nodes[leg.nodes.length - 1];
      var startN = N[leg.nodes[0]];
      var up = leg.startKind === 'vertical' && +leg.floor > +leg.fromFloor;
      var viaIn = leg.startVia && leg.startVia.type;
  
      if (n === 0) {
        if (leg.startKind === 'enter') push('enter', 'Come in through ' + entName(startN.ent) + ' — you’re at ' + theB(b));
        else if (leg.endKind === 'dest') push('dest', 'You’re already at ' + destRef(ctx));
        if (leg.endKind === 'vertical') push(vertIcon(leg), vertText(leg, 'right here'));
        return steps;
      }
      var startMerge = n >= 2 && runs[0].len < M(b, 15);
      var absorbLast = n >= 2 && runs[n - 1].len < M(b, 16) && (leg.endKind !== 'dest' || runs[n - 1].i1 - runs[n - 1].i0 === 1);
      if (startMerge && n === 2) absorbLast = false;
      var lastIdx = absorbLast ? n - 2 : n - 1;
  
      for (var r = 0; r <= lastIdx; r++) {
        var run = runs[r], isFinal = r === lastIdx;
        var lms = runLandmarks(leg, run, ctx, run.len > M(b, 35) ? 2 : 1);
        var area = runArea(leg, run, ctx);
        var past = (lms.length ? ' past ' + joinAnd(lms) : '') + (area ? (lms.length ? ', through ' : ' through ') + area : '');
        if (r === 0) {
          if (startMerge) {
            var t1 = turns[1], hall = hallWord(leg, runs[1]).indexOf('main') >= 0 ? 'the main hallway' : 'the hallway';
            var turnTxt = Math.abs(t1) >= 150 ? 'turn around' : (Math.abs(t1) < 55 ? 'bear ' : 'turn ') + sideWord(t1);
            if (Math.abs(t1) >= 150) turnTxt = 'turn around';
            var txt;
            if (leg.startKind === 'origin') {
              var around = roomAround(leg.fk, pts[0]);
              txt = 'Step out ' + (around ? 'of ' + withThe(around.say) + ' ' : '') + 'to ' + hall + ' and ' + turnTxt;
            } else if (leg.startKind === 'vertical') {
              txt = viaIn === 'elevator' ? 'Step off the elevator and ' + turnTxt : (up ? 'At the top of the stairs, ' : 'At the bottom of the stairs, ') + turnTxt;
            } else {
              txt = 'Come in through ' + entName(startN.ent) + ' and ' + turnTxt;
            }
            push(turnIcon(t1), txt);
          } else if (!past && run.len < M(b, 6) && leg.startKind !== 'enter') {
            prefix = leg.startKind === 'vertical' ? (leg.startVia.type === 'elevator' ? 'Off the elevator, ' : (+leg.floor > +leg.fromFloor ? 'At the top of the stairs, ' : 'At the bottom of the stairs, ')) : '';
          } else {
            push(leg.startKind === 'enter' ? 'enter' : 'straight', startText(leg, run, past, ctx, isFinal));
          }
          continue;
        }
        if (startMerge && r === 1) {
          if (past || (run.len > M(b, 25) && !isFinal) || (isFinal && leg.endKind === 'dest' && run.len > M(b, 30))) push('straight', 'Walk ' + hallWord(leg, run) + past);
          continue;
        }
        var t = turns[r], vg = leg.nodes[run.i0], jn = junction(vg, runs[r - 1].h, leg.fk), base;
        if (Math.abs(t) >= 150) base = 'Turn around';
        else if (Math.abs(t) < 55) base = 'Bear ' + sideWord(t);
        else if (jn === 'corner') base = 'Follow the hallway around the corner to the ' + sideWord(t);
        else if (jn === 'end') base = 'Turn ' + sideWord(t) + ' at the end of the hall';
        else {
          var bp = branchesPassed(leg, runs[r - 1], t);
          base = 'Turn ' + sideWord(t) + (bp === 0 ? ' at the next hallway' : bp < 4 ? ' at the ' + ORD[bp + 1] + ' hallway' : ' at the cross hallway');
        }
        var vr = (DOORS[vg] || []).filter(function (x) { return x !== ctx.room && x.say && !ctx.used[x.id] && lmScore(x) >= 3; })[0];
        if (vr) { ctx.used[vr.id] = 1; base += ', by ' + roomRef(vr); }
        if (past) base += ', then walk' + past;
        push(turnIcon(t), base);
      }
  
      // where the leg's end is, relative to the walker
      var lastRun = runs[lastIdx], where;
      if (absorbLast) {
        var tl = turns[n - 1];
        where = Math.abs(tl) >= 150 ? 'behind you' : 'on your ' + sideWord(tl);
      } else where = junction(endG, lastRun.h, leg.fk) === 'cross' ? 'straight ahead' : 'at the end of the hall';
  
      if (leg.endKind === 'vertical') push(vertIcon(leg), vertText(leg, where));
      else if (leg.endKind === 'exit') {
        var e = N[endG].ent, say = leg.endVia && leg.endVia.ref && leg.endVia.ref.say;
        push('exit', (say ? 'Head to ' : 'Go out ') + entName(e) + ' ' + where);
      } else if (leg.endKind === 'dest') push('dest', destText(leg, lastRun, absorbLast ? where : null, ctx, where));
      return steps;
    }
    function vertIcon(leg) {
      var down = +leg.toFloor < +leg.floor;
      return (leg.endVia.type === 'elevator' ? 'elevator-' : 'stairs-') + (down ? 'down' : 'up');
    }
    function vertText(leg, where) {
      var down = +leg.toFloor < +leg.floor, v = leg.endVia.ref;
      return 'Take ' + vertName(v) + ' ' + where + ' ' + (down ? 'down' : 'up') + ' to ' + levelLabel(leg.building, leg.toFloor);
    }
    function startText(leg, run, past, ctx, isFinal) {
      var startN = N[leg.nodes[0]], hw = hallWord(leg, run);
      if (leg.startKind === 'enter') return 'Come in through ' + entName(startN.ent) + ' and walk ' + hw + past;
      if (leg.startKind === 'vertical') {
        var up = +leg.floor > +leg.fromFloor;
        return (leg.startVia.type === 'elevator' ? 'Step off the elevator and walk ' : (up ? 'At the top of the stairs, walk ' : 'At the bottom of the stairs, walk ')) + hw + past;
      }
      var f = ctx.src.facing;
      if (f != null && f !== '') {
        var a = (+f) * Math.PI / 180, fv = [Math.sin(a), -Math.cos(a)], rel = angleBetween(fv, run.h);
        var lead = Math.abs(rel) < 35 ? 'Walk straight ahead ' : Math.abs(rel) > 145 ? 'Turn around and walk ' : 'Turn ' + sideWord(rel) + ' and walk ';
        return lead + hw.replace(/^straight /, '') + past;
      }
      // no facing known: point at something the student can see
      var endG = leg.nodes[run.i1], toward = null;
      var er = (DOORS[endG] || []).filter(function (x) { return x !== ctx.room && x.say && lmScore(x) >= 3; })[0];
      if (er) toward = roomRef(er);
      else if (N[endG].vert) toward = vertName(N[endG].vert);
      else if (N[endG].ent) toward = entName(N[endG].ent);
      else if (isFinal && ctx.room) toward = destRef(ctx);
      if (past) return 'Walk ' + hw + past + (toward && !/past/.test(toward) ? ' toward ' + toward : '');
      return toward ? 'Head ' + (hw === 'down the hallway' ? 'down the hallway ' : hw.indexOf('main') >= 0 ? 'down the main hallway ' : '') + 'toward ' + toward : 'Walk ' + hw;
    }
    function isAre(name) { return /^the restrooms$/i.test(name) || /[^s'\u2019]s(\s*\([^)]+\))?$/i.test(name) ? ' are ' : ' is '; }
    function destRef(ctx) { return ctx.room ? roomRef(ctx.room) : (ctx.tgt.kind === 'building' ? theB(ctx.tgt.b) : withThe(ctx.tgt.label)); }
    function destText(leg, run, absorbedWhere, ctx, where) {
      var room = ctx.room, name;
      if (!room) {
        if (ctx.tgt.kind === 'building') return 'You’ve reached ' + theB(ctx.tgt.b);
        if (ctx.tgt.kind === 'label') return cap(withThe(ctx.tgt.label)) + ' is right here';
        name = cap(withThe(ctx.tgt.kind === 'entrance' ? entName(ctx.tgt.ent) : ctx.tgt.label));
        return name + isAre(name) + (where || 'right ahead');
      }
      name = cap(roomRef(room));
      var IS = isAre(name);
      if (absorbedWhere) return name + IS + absorbedWhere;
      var dg = room.door, dp = xy(dg);
      if (!room.c) return name + IS + 'right here';
      var v = sub(room.c, dp), vl = len(v) || 1, cr = cross(run.h, v) / vl, dt = dot(run.h, v) / vl;
      if (Math.abs(cr) < 0.4 && dt > 0) return name + IS + 'straight ahead' + (junction(dg, run.h, leg.fk) === 'cross' ? '' : ' at the end of the hall');
      var side = cr > 0 ? 1 : -1, list = [], seen = {};
      for (var j = run.i0 + 1; j <= run.i1; j++) {
        var rs = DOORS[leg.nodes[j]] || [];
        var here = [];
        for (var k = 0; k < rs.length; k++) {
          var r = rs[k];
          if (!r.c || seen[r.id]) continue;
          var w = sub(r.c, xy(r.door)), c2 = cross(run.h, w) / (len(w) || 1);
          if (Math.abs(c2) < 0.4 || (c2 > 0 ? 1 : -1) !== side) continue;
          seen[r.id] = 1; here.push(r);
        }
        here.sort(function (p, q) { return dot(run.h, p.c) - dot(run.h, q.c); });
        list = list.concat(here);
      }
      var pos = list.indexOf(room) + 1, sw = side > 0 ? 'right' : 'left';
      if (pos >= 1 && pos <= 4) return name + IS + (IS === ' are ' ? 'through ' : '') + 'the ' + ORD[pos] + ' door on your ' + sw;
      return name + IS + 'on your ' + sw;
    }
    function outdoorSteps(leg, ctx) {
      var toB = N[leg.to].b, say = (leg.link.say || '').trim(), m = Math.round(leg.meters), text;
      var bname = B[toB] ? B[toB].name : toB;
      if (say) {
        text = /^(go|walk|head|take|exit|leave|cross|step|follow)\b/i.test(say) ? cap(say) : 'Go ' + say;
        if (lc(text).indexOf(lc(bname)) < 0) text += ' — ' + theB(toB);
      } else text = 'Walk outside to ' + theB(toB);
      return [{ icon: 'outdoor', text: text + ' (about ' + m + ' m)' }];
    }
  
    /* ================================================================ render */
    var SVGNS = 'http://www.w3.org/2000/svg', UID = 0;
    var KIND_COLORS = {
      office: ['#e4edfc', '#c3d5f5'], classroom: ['#fdf2dc', '#efd9a8'], lab: ['#efe7fc', '#d6c6f3'],
      restroom: ['#ddf2ef', '#b2ddd6'], stair: ['#e5e8ed', '#c9cfd8'], elevator: ['#e5e8ed', '#c9cfd8'],
      lobby: ['#e3f3e5', '#bfe0c4'], collab: ['#fde9e0', '#f2c9b5'], storage: ['#eceef1', '#d5d9df'],
      mech: ['#eceef1', '#d5d9df'], other: ['#f0f1f4', '#d8dbe1']
    };
    var C = { route: '#1a73e8', routeDark: '#0b57d0', start: '#1e8e3e', dest: '#ea4335', ground: '#e9edf1', building: '#fbfcfd', hall: '#eef1f5' };
    var ICONS = {
      straight: '<path d="M12 20V5M6.5 10.5 12 5l5.5 5.5"/>',
      left: '<path d="M16 20v-6a4 4 0 0 0-4-4H5M9.5 5.5 5 10l4.5 4.5"/>',
      right: '<path d="M8 20v-6a4 4 0 0 1 4-4h7M14.5 5.5 19 10l-4.5 4.5"/>',
      'slight-left': '<path d="M15 20v-5L7.5 7.5M7 13V7h6"/>',
      'slight-right': '<path d="M9 20v-5l7.5-7.5M11 7h6v6"/>',
      uturn: '<path d="M7 20V10a5 5 0 0 1 10 0v7M13 13.5l4 4 4-4"/>',
      'stairs-up': '<path d="M3 20h5v-4h4v-4h4V8h5M5 11V4M2.5 6.5 5 4l2.5 2.5"/>',
      'stairs-down': '<path d="M3 8h5v4h4v4h4v4h5M18 3v7M15.5 7.5 18 10l2.5-2.5"/>',
      'elevator-up': '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 10.5l3-3 3 3M9 14.5l3 3 3-3"/>',
      'elevator-down': '<rect x="5" y="3" width="14" height="18" rx="2"/><path d="M9 10.5l3-3 3 3M9 14.5l3 3 3-3"/>',
      exit: '<path d="M13 4H6v16h7M10 12h10M17 9l3 3-3 3"/>',
      enter: '<path d="M14 4h5v16h-5M3 12h11M11 9l3 3-3 3"/>',
      outdoor: '<circle cx="13.5" cy="4.5" r="1.8"/><path d="M10 21l2.5-6.5 2.5 2.5V21M8 12.5 10.5 8l3.5 1 2 3.5 2.5 1M10.5 8 9 14"/>',
      dest: '<path d="M12 21s-6.5-6-6.5-11.2a6.5 6.5 0 0 1 13 0C18.5 15 12 21 12 21z"/><circle cx="12" cy="9.8" r="2.3"/>',
      start: '<circle cx="12" cy="12" r="7.5"/><circle cx="12" cy="12" r="3" fill="currentColor"/>'
    };
    var ICON_TONE = {
      straight: 'blue', left: 'blue', right: 'blue', 'slight-left': 'blue', 'slight-right': 'blue', uturn: 'blue',
      'stairs-up': 'violet', 'stairs-down': 'violet', 'elevator-up': 'violet', 'elevator-down': 'violet',
      exit: 'teal', enter: 'teal', outdoor: 'teal', dest: 'red', start: 'green'
    };
    function iconSvg(name) {
      return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (ICONS[name] || ICONS.straight) + '</svg>';
    }
  
    var CSS = [
      '.qmap{all:initial;display:block;container-type:inline-size;width:100%;max-width:700px;font-family:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",sans-serif;font-size:14px;line-height:1.4;color:#1f2329;-webkit-font-smoothing:antialiased;text-align:left}',
      '.qmap div,.qmap span,.qmap b,.qmap i{box-sizing:border-box;margin:0;padding:0;border:0;font:inherit;color:inherit;letter-spacing:normal;text-transform:none;text-decoration:none;text-shadow:none;float:none;min-width:0;max-width:none;width:auto;height:auto;list-style:none;background:none;box-shadow:none;outline:0;position:static;transform:none;opacity:1;visibility:visible}',
      '.qmap svg{box-sizing:content-box;margin:0;padding:0;border:0;background:none;max-width:none;min-width:0;overflow:hidden;vertical-align:top}',
      '.qmap .qm-card{position:relative;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 1px 2px rgba(16,24,40,.06),0 12px 32px -6px rgba(16,24,40,.18);border:1px solid rgba(16,24,40,.06)}',
      '.qmap .qm-head{display:flex;align-items:center;gap:12px;padding:14px 16px 12px}',
      '.qmap .qm-pin{flex:0 0 38px;height:38px;border-radius:12px;background:#fdecea;color:#d93025;display:flex;align-items:center;justify-content:center}',
      '.qmap .qm-pin svg{width:22px;height:22px}',
      '.qmap .qm-tt{flex:1 1 auto;min-width:0}',
      '.qmap .qm-title{display:block;font-size:18px;font-weight:700;letter-spacing:-.01em;color:#111418;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.qmap .qm-sub{display:block;font-size:12.5px;color:#5f6773;margin-top:1px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
      '.qmap .qm-sub b{color:#1a5fd0;font-weight:650}',
      '.qmap .qm-eta{flex:0 0 auto;text-align:right;padding-left:8px}',
      '.qmap .qm-eta b{display:block;font-size:20px;font-weight:750;color:#188038;letter-spacing:-.02em;line-height:1.1}',
      '.qmap .qm-eta span{display:block;font-size:11.5px;color:#6b7280}',
      '.qmap .qm-close{flex:0 0 30px;height:30px;border-radius:50%;background:#f1f3f4;color:#5f6368;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:18px;line-height:1}',
      '.qmap .qm-close:hover{background:#e3e6e8}',
      '.qmap .qm-tabs{display:flex;align-items:center;gap:6px;flex-wrap:wrap;padding:0 16px 10px}',
      '.qmap .qm-tab{position:relative;overflow:hidden;cursor:pointer;display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 11px;border-radius:999px;background:#f1f3f4;color:#3c4043;font-size:12.5px;font-weight:600;transition:background .2s,color .2s}',
      '.qmap .qm-tab:hover{background:#e6e9ec}',
      '.qmap .qm-tab i{font-style:normal;display:inline-flex;align-items:center;justify-content:center;width:17px;height:17px;border-radius:50%;background:#fff;color:#3c4043;font-size:10.5px;font-weight:700}',
      '.qmap .qm-tab.on{background:#1a73e8;color:#fff}',
      '.qmap .qm-tab.on i{color:#1a73e8}',
      '.qmap .qm-tab .qm-prog{position:absolute;left:0;bottom:0;height:2px;width:0;background:rgba(255,255,255,.85)}',
      '.qmap .qm-tab.on .qm-prog.run{animation:qmap-prog var(--qm-dur,3.5s) linear forwards}',
      '.qmap .qm-arrow{color:#9aa0a6;font-size:12px}',
      '.qmap .qm-body{display:grid;grid-template-columns:minmax(0,1fr) 248px;border-top:1px solid #edf0f2}',
      '.qmap .qm-map{position:relative;height:var(--qm-h,320px);background:' + C.ground + ';overflow:hidden}',
      '.qmap .qm-map > svg{display:block;width:100%;height:100%}',
      '.qmap .qm-map.edit{cursor:crosshair}',
      '.qmap .qm-chip{position:absolute;left:10px;top:10px;padding:5px 10px;border-radius:9px;background:rgba(255,255,255,.94);box-shadow:0 1px 3px rgba(16,24,40,.16);font-size:12px;font-weight:650;color:#30353b}',
      '.qmap .qm-chip span{color:#7a828c;font-weight:500}',
      '.qmap .qm-compass{position:absolute;right:10px;top:10px;width:30px;height:30px;border-radius:50%;background:rgba(255,255,255,.94);box-shadow:0 1px 3px rgba(16,24,40,.16)}',
      '.qmap .qm-compass svg{width:30px;height:30px;display:block}',
      '.qmap .qm-hint{position:absolute;left:50%;bottom:10px;transform:translateX(-50%);padding:6px 12px;border-radius:999px;background:rgba(32,33,36,.86);color:#fff;font-size:12px;font-weight:600;white-space:nowrap}',
      '.qmap .qm-walkchip{background:#fff;color:#0b8077;box-shadow:0 2px 8px rgba(16,24,40,.16);display:flex;align-items:center;gap:8px}',
      '.qmap .qm-dots{display:inline-block;width:26px;height:0;border-top:4px dotted #1a73e8}',
      '.qmap .qm-steps{position:relative;border-left:1px solid #edf0f2;max-height:var(--qm-h,320px);overflow:auto;padding:8px 8px 10px}',
      '.qmap .qm-step{display:flex;gap:10px;align-items:flex-start;padding:7px 8px;border-radius:10px;font-size:13px;line-height:1.38;color:#8b9198;cursor:pointer;transition:color .25s,background .25s}',
      '.qmap .qm-step:hover{background:#f6f8fa}',
      '.qmap .qm-step.on{color:#202124}',
      '.qmap .qm-step.on.cur{background:#f2f6fe}',
      '.qmap .qm-ic{flex:0 0 26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#f1f3f4;color:#9aa0a6;transition:background .25s,color .25s;margin-top:-2px}',
      '.qmap .qm-ic svg{width:15px;height:15px}',
      '.qmap .qm-step.on .qm-ic.blue{background:#e8f0fe;color:#1a73e8}',
      '.qmap .qm-step.on .qm-ic.violet{background:#f3e8fd;color:#8430ce}',
      '.qmap .qm-step.on .qm-ic.teal{background:#e0f3f1;color:#0b8077}',
      '.qmap .qm-step.on .qm-ic.red{background:#fdecea;color:#d93025}',
      '.qmap .qm-step.on .qm-ic.green{background:#e6f4ea;color:#188038}',
      '.qmap .qm-foot{display:flex;justify-content:space-between;gap:8px;padding:8px 8px 0;margin-top:4px;border-top:1px dashed #e3e6ea;font-size:11.5px;color:#80868b}',
      '.qmap .qm-out{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;gap:10px;padding:20px;background:linear-gradient(180deg,#eef6ee,#e6efe8)}',
      '.qmap .qm-ob{flex:0 1 150px;background:#fff;border-radius:14px;padding:12px;box-shadow:0 2px 8px rgba(16,24,40,.1);text-align:center}',
      '.qmap .qm-ob .qm-ic{margin:0 auto 6px;width:34px;height:34px;flex-basis:auto;background:#e0f3f1;color:#0b8077}',
      '.qmap .qm-ob .qm-ic svg{width:19px;height:19px}',
      '.qmap .qm-ob b{display:block;font-size:13px;font-weight:700;color:#202124}',
      '.qmap .qm-ob span{display:block;font-size:11.5px;color:#6b7280;margin-top:2px}',
      '.qmap .qm-walk{flex:1 1 90px;max-width:170px;text-align:center;font-size:12px;color:#0b8077;font-weight:650}',
      '.qmap .qm-walk i{display:block;height:0;border-top:4px dotted #1a73e8;margin:6px 0}',
      '.qmap .qm-walk span{display:block;color:#5f6773;font-weight:500;font-size:11.5px}',
      '.qmap .qm-empty{padding:18px;font-size:13px;color:#5f6368}',
      '.qmap svg text{font-family:system-ui,-apple-system,"Segoe UI Variable Text","Segoe UI",Roboto,"Helvetica Neue",sans-serif}',
      '.qmap .qm-draw{animation:qmap-draw .9s cubic-bezier(.3,.7,.3,1) both}',
      '.qmap .qm-flow{animation:qmap-flow 1.1s linear infinite,qmap-fade .4s .8s both}',
      '.qmap .qm-late{animation:qmap-fade .4s .75s both}',
      '.qmap .qm-pulse{transform-box:fill-box;transform-origin:center;animation:qmap-pulse 1.9s ease-out infinite}',
      '.qmap .qm-drop{animation:qmap-drop .5s .7s cubic-bezier(.3,1.5,.5,1) both}',
      '.qmap .qm-fadein{animation:qmap-fade .3s both}',
      '@keyframes qmap-draw{from{stroke-dashoffset:1}to{stroke-dashoffset:0}}',
      '@keyframes qmap-flow{from{stroke-dashoffset:0}to{stroke-dashoffset:-1}}',
      '@keyframes qmap-fade{from{opacity:0}to{opacity:1}}',
      '@keyframes qmap-pulse{0%{transform:scale(.5);opacity:.55}100%{transform:scale(2.6);opacity:0}}',
      '@keyframes qmap-drop{from{opacity:0;transform:translateY(-14px)}to{opacity:1;transform:none}}',
      '@keyframes qmap-prog{from{width:0}to{width:100%}}',
      '@container (max-width:560px){.qmap .qm-sub{white-space:normal}.qmap .qm-body{grid-template-columns:1fr}.qmap .qm-steps{border-left:0;border-top:1px solid #edf0f2;max-height:none}.qmap .qm-eta b{font-size:17px}}',
      '@media (prefers-reduced-motion:reduce){.qmap .qm-flow,.qmap .qm-pulse{animation:none}}'
    ].join('\n');
  
    function injectCss(doc) {
      if (doc.getElementById('qmap-css')) return;
      var st = doc.createElement('style');
      st.id = 'qmap-css'; st.textContent = CSS;
      (doc.head || doc.documentElement).appendChild(st);
    }
    function S(tag, attrs, parent) {
      var e = document.createElementNS(SVGNS, tag);
      if (attrs) for (var k in attrs) if (attrs.hasOwnProperty(k) && attrs[k] != null) e.setAttribute(k, attrs[k]);
      if (parent) parent.appendChild(e);
      return e;
    }
    function H(tag, cls, parent, html) {
      var e = document.createElement(tag);
      if (cls) e.className = cls;
      if (html != null) e.innerHTML = html;
      if (parent) parent.appendChild(e);
      return e;
    }
    function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
    function f1(v) { return Math.round(v * 10) / 10; }
    function roundedPath(pts, r) {
      var n = pts.length, d = '';
      for (var i = 0; i < n; i++) {
        var p0 = pts[(i - 1 + n) % n], p1 = pts[i], p2 = pts[(i + 1) % n];
        var v1 = sub(p0, p1), v2 = sub(p2, p1), l1 = len(v1), l2 = len(v2);
        var rr = Math.min(r, l1 / 2, l2 / 2);
        var a = [p1[0] + v1[0] / (l1 || 1) * rr, p1[1] + v1[1] / (l1 || 1) * rr];
        var b = [p1[0] + v2[0] / (l2 || 1) * rr, p1[1] + v2[1] / (l2 || 1) * rr];
        d += (i ? 'L' : 'M') + f1(a[0]) + ' ' + f1(a[1]) + 'Q' + f1(p1[0]) + ' ' + f1(p1[1]) + ' ' + f1(b[0]) + ' ' + f1(b[1]);
      }
      return d + 'Z';
    }
    function polyD(pts) { return 'M' + pts.map(function (p) { return f1(p[0]) + ' ' + f1(p[1]); }).join('L'); }
    function pathLen(pts) { var L = 0; for (var i = 1; i < pts.length; i++) L += dist(pts[i - 1], pts[i]); return L; }
    function textW(s, fs, bold) { return String(s).length * fs * (bold ? 0.6 : 0.54); }
  
    // viewBox around the interesting points, keeping context and the viewport's aspect
    function fitBox(pts, extent, aspect, minFrac, padFrac) {
      var bb = bbox(pts), w = bb[2] - bb[0], h = bb[3] - bb[1];
      var ew = extent[2] - extent[0], eh = extent[3] - extent[1];
      var pad = padFrac != null ? padFrac * Math.max(w, h) : Math.max(ew * 0.08, 0.22 * Math.max(w, h));
      var x0 = bb[0] - pad, y0 = bb[1] - pad, x1 = bb[2] + pad, y1 = bb[3] + pad;
      var minW = ew * (minFrac || 0.5);
      if (x1 - x0 < minW) { var cx = (x0 + x1) / 2; x0 = cx - minW / 2; x1 = cx + minW / 2; }
      w = x1 - x0; h = y1 - y0;
      if (w / h < aspect) { var nw = h * aspect, mx = (x0 + x1) / 2; x0 = mx - nw / 2; w = nw; }
      else { var nh = w / aspect, my = (y0 + y1) / 2; y0 = my - nh / 2; h = nh; }
      var m = Math.max(ew, eh) * 0.05, fx0 = extent[0] - m, fy0 = extent[1] - m, fx1 = extent[2] + m, fy1 = extent[3] + m;
      if (w >= fx1 - fx0) x0 = (fx0 + fx1) / 2 - w / 2; else { if (x0 < fx0) x0 = fx0; if (x0 + w > fx1) x0 = fx1 - w; }
      if (h >= fy1 - fy0) y0 = (fy0 + fy1) / 2 - h / 2; else { if (y0 < fy0) y0 = fy0; if (y0 + h > fy1) y0 = fy1 - h; }
      return [x0, y0, w, h];
    }
  
    var PLACED = null;   // boxes [x0,y0,x1,y1] already used on the current map
    function hits(b) {
      if (!PLACED) return false;
      for (var i = 0; i < PLACED.length; i++) { var p = PLACED[i]; if (b[0] < p[2] && b[2] > p[0] && b[1] < p[3] && b[3] > p[1]) return true; }
      return false;
    }
    function claim(b) { if (PLACED) PLACED.push(b); }
    function bubble(g, x, y, text, upp, tone, vb, below) {
      var fs = 11.5 * upp, padX = 8 * upp, h = 22 * upp, w = textW(text, fs, true) + padX * 2;
      function clampX(bx) { return Math.max(vb[0] + 4 * upp, Math.min(bx, vb[0] + vb[2] - 4 * upp - w)); }
      var above = [clampX(x - w / 2), y - h - 10 * upp], under = [clampX(x - w / 2), y + 18 * upp];
      var side = [x + 16 * upp, y - h / 2], other = [x - 16 * upp - w, y - h / 2];
      var tries = below ? [under, above, side, other] : [above, under, side, other], pos = null;
      for (var k = 0; k < tries.length && !pos; k++) {
        var c = tries[k], bb = [c[0], c[1], c[0] + w, c[1] + h];
        if (c[1] < vb[1] + 2 * upp || c[1] + h > vb[1] + vb[3] - 2 * upp || c[0] < vb[0] || c[0] + w > vb[0] + vb[2]) continue;
        if (!hits(bb)) pos = c;
      }
      if (!pos) pos = tries[0][1] < vb[1] + 2 * upp ? tries[1] : tries[0];
      var bx = pos[0], by = pos[1];
      claim([bx - 2 * upp, by - 2 * upp, bx + w + 2 * upp, by + h + 2 * upp]);
      var grp = S('g', { 'class': 'qm-late' }, g);
      S('rect', { x: f1(bx), y: f1(by + 1.2 * upp), width: f1(w), height: f1(h), rx: f1(h / 2), fill: 'rgba(16,24,40,.18)' }, grp);
      S('rect', { x: f1(bx), y: f1(by), width: f1(w), height: f1(h), rx: f1(h / 2), fill: tone === 'white' ? '#fff' : tone, stroke: tone === 'white' ? '#dadce0' : 'none', 'stroke-width': f1(upp) }, grp);
      var t = S('text', { x: f1(bx + w / 2), y: f1(by + h / 2 + fs * 0.36), 'text-anchor': 'middle', 'font-size': f1(fs), 'font-weight': 700, fill: tone === 'white' ? '#202124' : '#fff' }, grp);
      t.textContent = text;
    }
    function badge(g, x, y, icon, upp, color, reserve) {
      var s = 22 * upp, grp = S('g', { transform: 'translate(' + f1(x) + ' ' + f1(y) + ')' }, g);
      S('circle', { r: f1(s / 2 + 1.5 * upp), fill: '#fff' }, grp);
      S('circle', { r: f1(s / 2), fill: color || '#5f6368' }, grp);
      var ic = S('g', { transform: 'translate(' + f1(-s * 0.32) + ' ' + f1(-s * 0.32) + ') scale(' + f1(s * 0.64 / 24 * 1000) / 1000 + ')', fill: 'none', stroke: '#fff', 'stroke-width': 2.4, 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, grp);
      ic.innerHTML = ICONS[icon] || '';
      if (reserve) claim([x - s / 2 - 2 * upp, y - s / 2 - 2 * upp, x + s / 2 + 2 * upp, y + s / 2 + 2 * upp]);
      return grp;
    }
  
    function drawFloor(svg, view, route, px, opts) {
      var fr = FLOORS[view.fk], leg = view.leg, uid = view.uid;
      var extent = fr.outline ? bbox(fr.outline.concat([[0, 0]])) : [0, 0, fr.width, fr.height];
      if (fr.outline) { var ob = bbox(fr.outline); extent = [Math.min(ob[0], 0), Math.min(ob[1], 0), Math.max(ob[2], fr.width), Math.max(ob[3], fr.height)]; }
      var focus = [], room = view.room;
      if (leg && leg.points.length) focus = focus.concat(leg.points);
      if (room && room.bb) focus.push([room.bb[0], room.bb[1]], [room.bb[2], room.bb[3]]);
      if (view.pin) focus.push(view.pin);
      if (!focus.length) focus = [[extent[0], extent[1]], [extent[2], extent[3]]];
      var vb = view.full ? fitBox([[extent[0], extent[1]], [extent[2], extent[3]]], extent, px.w / px.h, 1, 0.04) : fitBox(focus, extent, px.w / px.h, 0.5);
      var upp = vb[2] / px.w;
      svg.setAttribute('viewBox', vb.map(f1).join(' '));
      svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
      var defs = S('defs', null, svg);
      var flt = S('filter', { id: 'qmsh' + uid, x: '-10%', y: '-10%', width: '120%', height: '120%' }, defs);
      S('feDropShadow', { dx: 0, dy: f1(2 * upp), stdDeviation: f1(5 * upp), 'flood-color': '#1b2a41', 'flood-opacity': 0.13 }, flt);
      var rf = S('filter', { id: 'qmrs' + uid, x: '-20%', y: '-20%', width: '140%', height: '140%' }, defs);
      S('feDropShadow', { dx: 0, dy: f1(1.5 * upp), stdDeviation: f1(2 * upp), 'flood-color': '#0b57d0', 'flood-opacity': 0.35 }, rf);
  
      S('rect', { x: f1(vb[0] - vb[2]), y: f1(vb[1] - vb[3]), width: f1(vb[2] * 3), height: f1(vb[3] * 3), fill: C.ground }, svg);
      // building
      var outline = fr.outline || rectPoly([0, 0, fr.width, fr.height]);
      S('path', { d: roundedPath(outline, 14 * upp), fill: C.building, stroke: '#c9d0da', 'stroke-width': f1(1.5 * upp), filter: 'url(#qmsh' + uid + ')' }, svg);
      // hallways
      var hw = Math.max(14 * upp, Math.min(26, 3 / mpu(fr.b)));
      var halls = S('g', { stroke: C.hall, 'stroke-width': f1(hw), 'stroke-linecap': 'round', fill: 'none' }, svg);
      for (var i = 0; i < fr.edges.length; i++) {
        var a = N[fr.edges[i][0]], b = N[fr.edges[i][1]];
        if (!a || !b || a.kind === 'desk' || b.kind === 'desk') continue;
        S('line', { x1: f1(a.x), y1: f1(a.y), x2: f1(b.x), y2: f1(b.y) }, halls);
      }
      PLACED = [];
      var mk = S('g', null, null);
      drawMarkers(mk, view, route, upp, vb);
      // rooms
      var rg = S('g', null, svg), lg = S('g', { 'pointer-events': 'none' }, svg);
      var order = fr.rooms.slice().sort(function (a, b) { return area(b) - area(a); });
      var gap = 1.6 * upp;
      for (i = 0; i < fr.rooms.length; i++) {
        var r = fr.rooms[i];
        if (!r.poly || r.poly.length < 3) continue;
        var col = KIND_COLORS[r.kind] || KIND_COLORS.other, isDest = room === r;
        var bw = r.bb[2] - r.bb[0], bh = r.bb[3] - r.bb[1];
        var rad = Math.min(7 * upp, bw * 0.18, bh * 0.18);
        S('path', {
          d: roundedPath(r.poly, rad), fill: isDest ? '#fde3e0' : col[0], stroke: isDest ? C.dest : '#fff',
          'stroke-width': f1(isDest ? 2.4 * upp : gap * 2), 'stroke-linejoin': 'round'
        }, rg);
        if (!isDest) S('path', { d: roundedPath(r.poly, rad), fill: 'none', stroke: col[1], 'stroke-width': f1(0.8 * upp), opacity: 0.9 }, rg);
      }
      for (i = 0; i < order.length; i++) if (order[i].poly && order[i].bb && order[i] !== room) roomLabel(lg, order[i], upp);
      // area labels
      for (i = 0; i < fr.labels.length; i++) {
        var lb = fr.labels[i], txt = speak(lb.text).toUpperCase(), fsA = 10.5 * upp, wA = txt.length * fsA * 0.72;
        var boxA = [lb.x - wA / 2, lb.y - fsA, lb.x + wA / 2, lb.y + fsA * 0.3];
        if (!txt || hits(boxA)) continue;
        claim(boxA);
        var t = S('text', { x: f1(lb.x), y: f1(lb.y), 'text-anchor': 'middle', 'font-size': f1(fsA), 'font-weight': 700, fill: '#8a93a0', 'letter-spacing': f1(1.4 * upp) }, lg);
        t.textContent = txt;
      }
      // stairs / elevators / entrances
      var icons = S('g', null, svg);
      for (i = 0; i < fr.verts.length; i++) {
        var vn = N[fr.verts[i]];
        badge(icons, vn.x, vn.y, vn.kind === 'elevator' ? 'elevator-up' : 'stairs-up', upp * 0.85, '#7b8594');
      }
      for (i = 0; i < fr.ents.length; i++) {
        var en = N[fr.ents[i]];
        badge(icons, en.x, en.y, 'enter', upp * 0.78, '#0b8077');
      }
  
      if (leg && leg.points.length > 1) drawRoute(svg, leg.points, upp, uid);
      svg.appendChild(mk);
      PLACED = null;
      view.vb = vb; view.upp = upp;
    }
    function drawMarkers(mk, view, route, upp, vb) {
      var leg = view.leg;
      if (leg && leg.points.length) {
        var p0 = leg.points[0], pe = leg.points[leg.points.length - 1];
        claim(leg.endKind === 'dest' ? [pe[0] - 12 * upp, pe[1] - 34 * upp, pe[0] + 12 * upp, pe[1] + 3 * upp] : [pe[0] - 14 * upp, pe[1] - 14 * upp, pe[0] + 14 * upp, pe[1] + 14 * upp]);
        claim([p0[0] - 10 * upp, p0[1] - 10 * upp, p0[0] + 10 * upp, p0[1] + 10 * upp]);
        var p1 = leg.points[1] || p0, goesUp = p1[1] < p0[1] && Math.abs(p1[1] - p0[1]) > Math.abs(p1[0] - p0[0]);
        if (leg.startKind === 'origin') youAreHere(mk, p0, upp, vb, route && route.from && route.from.desk ? 'You are here' : 'Start', goesUp);
        else if (leg.startKind === 'vertical') {
          badge(mk, p0[0], p0[1], (leg.viaIn === 'elevator' ? 'elevator-' : 'stairs-') + (+leg.floor < +leg.fromFloor ? 'down' : 'up'), upp * 1.15, '#8430ce', true);
          bubble(mk, p0[0], p0[1] - 6 * upp, 'From ' + levelLabel(leg.building, leg.fromFloor), upp, 'white', vb, goesUp);
        } else if (leg.startKind === 'enter') {
          badge(mk, p0[0], p0[1], 'enter', upp * 1.15, '#0b8077', true);
          bubble(mk, p0[0], p0[1] - 6 * upp, 'Enter here', upp, '#0b8077', vb, goesUp);
        } else ringMarker(mk, p0, upp, C.route);
        if (leg.endKind === 'dest') destPin(mk, pe, upp, vb, route.to.num ? (route.to.name ? route.to.num + ' · ' + route.to.name : 'Room ' + route.to.num) : route.to.label);
        else if (leg.endKind === 'vertical') {
          badge(mk, pe[0], pe[1], (leg.via === 'elevator' ? 'elevator-' : 'stairs-') + (+leg.toFloor < +leg.floor ? 'down' : 'up'), upp * 1.15, '#8430ce', true);
          bubble(mk, pe[0], pe[1] - 6 * upp, (+leg.toFloor < +leg.floor ? 'Down to ' : 'Up to ') + levelLabel(leg.building, leg.toFloor), upp, '#8430ce', vb);
        } else if (leg.endKind === 'exit') {
          badge(mk, pe[0], pe[1], 'exit', upp * 1.15, '#0b8077', true);
          bubble(mk, pe[0], pe[1] - 6 * upp, 'Exit here', upp, '#0b8077', vb);
        }
      } else if (view.pin) {
        youAreHere(mk, view.pin, upp, vb, 'You are here');
      }
    }
    function area(r) { return r.bb ? (r.bb[2] - r.bb[0]) * (r.bb[3] - r.bb[1]) : 0; }
    function roomLabel(g, r, upp) {
      var bw = (r.bb[2] - r.bb[0]) / upp, bh = (r.bb[3] - r.bb[1]) / upp, c = r.c;
      var fsN = 10.5, fsT = 9.5, name = r.say, lines = [];
      if (!hasNum(r) && !name) return;
      if (bw < 22 || bh < 13) return;
      if (hasNum(r) && textW(r.num, fsN, true) > bw * 0.92) fsN = 8.5;
      if (hasNum(r) && textW(r.num, fsN, true) > bw * 0.92) return;
      if (name && bh >= 30) {
        var words = name.split(/\s+/), line = '', maxW = bw * 0.86;
        for (var i = 0; i < words.length; i++) {
          var tryL = line ? line + ' ' + words[i] : words[i];
          if (textW(tryL, fsT) <= maxW) line = tryL;
          else { if (line) lines.push(line); line = words[i]; }
        }
        if (line) lines.push(line);
        var maxLines = Math.max(0, Math.floor((bh - (hasNum(r) ? 16 : 4)) / 12));
        if (lines.length > Math.min(2, maxLines) || lines.some(function (l) { return textW(l, fsT) > maxW; })) lines = [];
      }
      var shownNum = hasNum(r) ? r.num : '';
      if (!shownNum && !lines.length) return;
      function boxFor(ls) {
        var tw = Math.max(shownNum ? textW(shownNum, fsN, true) : 0, ls.reduce(function (m, l) { return Math.max(m, textW(l, fsT)); }, 0));
        var th = (shownNum ? fsN + 3 : 0) + ls.length * (fsT + 2.5);
        return [c[0] - tw / 2 * upp, c[1] - th / 2 * upp, c[0] + tw / 2 * upp, c[1] + th / 2 * upp];
      }
      var bx = boxFor(lines);
      if (hits(bx) && lines.length && shownNum) { lines = []; bx = boxFor(lines); }
      if (hits(bx)) return;
      claim(bx);
      var total = (shownNum ? fsN : 0) + lines.length * (fsT + 2.5), y = c[1] / upp - total / 2 + (shownNum ? fsN * 0.82 : fsT * 0.8);
      if (shownNum) {
        var t = S('text', { x: f1(c[0]), y: f1(y * upp), 'text-anchor': 'middle', 'font-size': f1(fsN * upp), 'font-weight': 700, fill: '#3c4350' }, g);
        t.textContent = shownNum; y += fsT + 3;
      }
      for (var k = 0; k < lines.length; k++) {
        var t2 = S('text', { x: f1(c[0]), y: f1(y * upp), 'text-anchor': 'middle', 'font-size': f1(fsT * upp), 'font-weight': 500, fill: '#5d6572' }, g);
        t2.textContent = lines[k]; y += fsT + 2.5;
      }
    }
    function drawRoute(svg, pts, upp, uid) {
      var d = polyD(pts), L = pathLen(pts) / upp;
      var g = S('g', { fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
      S('path', { d: d, stroke: '#fff', 'stroke-width': f1(11 * upp), pathLength: 1, 'stroke-dasharray': 1, 'class': 'qm-draw', filter: 'url(#qmrs' + uid + ')' }, g);
      S('path', { d: d, stroke: C.route, 'stroke-width': f1(7 * upp), pathLength: 1, 'stroke-dasharray': 1, 'class': 'qm-draw' }, g);
      var periods = Math.max(2, Math.round(L / 26));
      S('path', { d: d, stroke: 'rgba(255,255,255,.55)', 'stroke-width': f1(2.6 * upp), pathLength: periods, 'stroke-dasharray': '0.22 0.78', 'class': 'qm-flow' }, g);
      // chevrons
      var ch = S('g', { 'class': 'qm-late', stroke: '#fff', 'stroke-width': f1(2 * upp), fill: 'none', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }, svg);
      var step = 58 * upp, acc = step * 0.6, s = 3 * upp;
      for (var i = 1; i < pts.length; i++) {
        var a = pts[i - 1], b = pts[i], sl = dist(a, b), h = unit(sub(b, a));
        while (acc < sl) {
          var ttl = pathLen(pts.slice(0, i)) + acc;
          if (ttl > 16 * upp && pathLen(pts) - ttl > 24 * upp) {
            var x = a[0] + h[0] * acc, y = a[1] + h[1] * acc, nx = -h[1], ny = h[0];
            S('path', { d: 'M' + f1(x - h[0] * s + nx * s * 1.2) + ' ' + f1(y - h[1] * s + ny * s * 1.2) + 'L' + f1(x + h[0] * s) + ' ' + f1(y + h[1] * s) + 'L' + f1(x - h[0] * s - nx * s * 1.2) + ' ' + f1(y - h[1] * s - ny * s * 1.2) }, ch);
          }
          acc += step;
        }
        acc -= sl;
      }
    }
    function youAreHere(g, p, upp, vb, label, below) {
      var grp = S('g', null, g);
      S('circle', { cx: f1(p[0]), cy: f1(p[1]), r: f1(9 * upp), fill: C.start, opacity: 0.35, 'class': 'qm-pulse' }, grp);
      S('circle', { cx: f1(p[0]), cy: f1(p[1]), r: f1(13 * upp), fill: C.start, opacity: 0.12 }, grp);
      S('circle', { cx: f1(p[0]), cy: f1(p[1]), r: f1(8 * upp), fill: '#fff' }, grp);
      S('circle', { cx: f1(p[0]), cy: f1(p[1]), r: f1(5.6 * upp), fill: C.start }, grp);
      bubble(grp, p[0], below ? p[1] : p[1] - 6 * upp, label, upp, C.start, vb, below);
      return grp;
    }
    function ringMarker(g, p, upp, color) {
      S('circle', { cx: f1(p[0]), cy: f1(p[1]), r: f1(7 * upp), fill: '#fff', stroke: color, 'stroke-width': f1(3 * upp) }, g);
    }
    function destPin(g, p, upp, vb, label) {
      var grp = S('g', { 'class': 'qm-drop' }, g);
      S('ellipse', { cx: f1(p[0]), cy: f1(p[1]), rx: f1(6 * upp), ry: f1(2.4 * upp), fill: 'rgba(0,0,0,.22)' }, grp);
      var pin = S('g', { transform: 'translate(' + f1(p[0]) + ' ' + f1(p[1]) + ') scale(' + (Math.round(upp * 1000) / 1000) + ')' }, grp);
      S('path', { d: 'M0 0C-2 -6 -11 -12 -11 -21A11 11 0 1 1 11 -21C11 -12 2 -6 0 0Z', fill: C.dest, stroke: '#b3261e', 'stroke-width': 1 }, pin);
      S('circle', { cx: 0, cy: -21, r: 4.2, fill: '#fff' }, pin);
      bubble(grp, p[0], p[1] - 30 * upp, label, upp, 'white', vb);
    }
  
    function drawCampus(svg, view, route, px) {
      var Lay = CAMPUS.layout, leg = view.leg, pts = [], focus = [], k;
      for (k in Lay) if (Lay.hasOwnProperty(k)) {
        var L = Lay[k], c4 = [[L.x, L.y], [L.x + L.w, L.y + L.h]];
        pts.push(c4[0], c4[1]);
        if (k === leg.fromBuilding || k === leg.toBuilding) focus.push(c4[0], c4[1]);
      }
      var ext = bbox(pts), vb = fitBox(focus.length ? focus : pts, ext, px.w / px.h, 0.3, 0.18), upp = vb[2] / px.w, uid = view.uid;
      svg.setAttribute('viewBox', vb.map(f1).join(' '));
      var defs = S('defs', null, svg), flt = S('filter', { id: 'qmsh' + uid, x: '-10%', y: '-10%', width: '120%', height: '120%' }, defs);
      S('feDropShadow', { dx: 0, dy: f1(2 * upp), stdDeviation: f1(4 * upp), 'flood-color': '#1b2a41', 'flood-opacity': 0.16 }, flt);
      S('rect', { x: f1(vb[0] - vb[2]), y: f1(vb[1] - vb[3]), width: f1(vb[2] * 3), height: f1(vb[3] * 3), fill: '#e4eedf' }, svg);
      for (k in Lay) if (Lay.hasOwnProperty(k)) {
        var l = Lay[k], cx = l.x + l.w / 2, cy = l.y + l.h / 2, on = k === leg.fromBuilding || k === leg.toBuilding;
        var g = S('g', { transform: 'rotate(' + (l.rot || 0) + ' ' + f1(cx) + ' ' + f1(cy) + ')' }, svg);
        S('rect', { x: f1(l.x), y: f1(l.y), width: f1(l.w), height: f1(l.h), rx: f1(Math.min(16 * upp, l.w * 0.15)), fill: on ? '#ffffff' : '#f4f5f7', stroke: on ? '#aab6c6' : '#d0d6de', 'stroke-width': f1(1.4 * upp), filter: 'url(#qmsh' + uid + ')' }, g);
        var nm = B[k] ? B[k].name : k, fs = 12 * upp, ty = l.h / upp > 70 ? l.y + 24 * upp : cy + fs * 0.35;
        var t = S('text', { x: f1(cx), y: f1(ty), 'text-anchor': 'middle', 'font-size': f1(fs), 'font-weight': 700, fill: on ? '#2b3138' : '#8a929c', transform: 'rotate(' + (l.rot || 0) + ' ' + f1(cx) + ' ' + f1(cy) + ')' }, svg);
        t.textContent = nm;
      }
      if (leg.points.length > 1) {
        var d = polyD(leg.points);
        S('path', { d: d, stroke: '#fff', 'stroke-width': f1(9 * upp), fill: 'none', 'stroke-linecap': 'round', opacity: 0.8 }, svg);
        S('path', { d: d, stroke: C.route, 'stroke-width': f1(6 * upp), fill: 'none', 'stroke-linecap': 'round', 'stroke-dasharray': '0 ' + f1(11 * upp), 'class': 'qm-fadein' }, svg);
        var a = leg.points[0], b = leg.points[leg.points.length - 1];
        badge(svg, a[0], a[1], 'exit', upp * 0.9, '#5f6368');
        badge(svg, b[0], b[1], 'enter', upp * 0.9, '#0b8077');
      }
      view.vb = vb; view.upp = upp;
    }
  
    function buildViews(route, opts) {
      var views = [];
      if (!route) {
        var d = DESK && N[DESK.gid];
        var fk = opts.floorKey || (d ? d.fk : (BLIST[0] && BLIST[0].floors[0] && BLIST[0].floors[0].key));
        if (fk) views.push({ kind: 'floor', fk: fk, leg: null, pin: d && d.fk === fk ? [d.x, d.y] : null, full: true, tab: FLOORS[fk].label });
        return views;
      }
      for (var i = 0; i < route.legs.length; i++) {
        var L = route.legs[i];
        if (L.kind === 'outdoor') {
          views.push({ kind: CAMPUS.layout && L.points.length > 1 ? 'campus' : 'card', leg: L, tab: 'Outside' });
        } else {
          views.push({
            kind: 'floor', fk: L.building + '|' + L.floor, leg: L,
            room: L.endKind === 'dest' && route.to.kind === 'room' ? ROOMS[route.to.id] : null,
            tab: (route.legs.some(function (x) { return x.kind === 'indoor' && x.building !== L.building; }) ? L.building + ' · ' : '') + levelLabel(L.building, L.floor)
          });
        }
      }
      return views;
    }
  
    function render(container, route, opts) {
      opts = opts || {};
      var doc = container.ownerDocument || document;
      injectCss(doc);
      container.innerHTML = '';
      var root = H('div', 'qmap', container);
      var card = H('div', 'qm-card', root);
      var timer = null, cur = 0, views = buildViews(route, opts), dead = false;
      var interval = opts.interval || CFG.autoAdvanceMs, mapH = opts.mapHeight || CFG.mapHeight;
      root.style.setProperty('--qm-h', mapH + 'px');
      root.style.setProperty('--qm-dur', (interval / 1000) + 's');
      // header
      var head = H('div', 'qm-head', card);
      if (route) {
        H('div', 'qm-pin', head, iconSvg('dest'));
        var tt = H('div', 'qm-tt', head);
        var t = route.to, title = opts.title || (t.kind === 'room' ? (t.name ? t.name : 'Room ' + t.num) : t.label);
        var place = (B[t.building] ? B[t.building].name : t.building) + ' · ' + levelLabel(t.building, t.floor);
        H('div', 'qm-title', tt, esc(title));
        H('div', 'qm-sub', tt, (t.kind === 'room' && t.name ? 'Room ' + esc(t.num) + ' · ' : '') + esc(place) + ' · <b>' + esc(route.summary.split(' — ')[0]) + '</b>');
        H('div', 'qm-eta', head, '<b>' + route.minutes + ' min</b><span>' + route.meters + ' m walk</span>');
      } else {
        H('div', 'qm-pin', head, iconSvg('start')).style.cssText = 'background:#e6f4ea;color:#188038';
        var tt2 = H('div', 'qm-tt', head);
        H('div', 'qm-title', tt2, esc(opts.title || (opts.edit ? 'Set “You are here”' : 'Campus map')));
        H('div', 'qm-sub', tt2, esc(opts.edit ? 'Click the hallway where the front desk is' : (views[0] ? views[0].tab : '')));
      }
      if (opts.onClose) { var cl = H('div', 'qm-close', head, '×'); cl.setAttribute('role', 'button'); cl.onclick = function () { destroy(); opts.onClose(); }; }
      // tabs
      var tabs = [];
      if (views.length > 1) {
        var tb = H('div', 'qm-tabs', card);
        views.forEach(function (v, i) {
          if (i) H('span', 'qm-arrow', tb, '›');
          var b = H('div', 'qm-tab', tb, '<i>' + (i + 1) + '</i>' + esc(v.tab) + '<span class="qm-prog"></span>');
          b.setAttribute('role', 'button');
          b.onclick = function () { stop(); show(i); };
          tabs.push(b);
        });
      }
      var body = H('div', 'qm-body', card);
      var mapEl = H('div', 'qm-map' + (opts.edit ? ' edit' : ''), body);
      var stepEls = [], stepList = null;
      if (route) {
        var sl = stepList = H('div', 'qm-steps', body);
        route.steps.forEach(function (s) {
          var row = H('div', 'qm-step', sl, '<span class="qm-ic ' + (ICON_TONE[s.icon] || 'blue') + '">' + iconSvg(s.icon) + '</span><span>' + esc(s.text) + '</span>');
          row.onclick = function () { stop(); show(s.leg); };
          stepEls.push(row);
        });
        H('div', 'qm-foot', sl, '<span>' + route.meters + ' m · ' + route.minutes + ' min</span><span>' + (route.avoidStairs ? 'Step-free route' : 'From ' + esc(route.from.label)) + '</span>');
      } else {
        body.style.gridTemplateColumns = '1fr';
      }
  
      var shown = false;
      function show(i) {
        if (dead || !views.length) return;
        setTimeout(function () { shown = true; }, 0);
        cur = i;
        var v = views[i];
        v.uid = ++UID;
        mapEl.innerHTML = '';
        var w = mapEl.clientWidth || (opts.width ? opts.width : 420), h = mapEl.clientHeight || mapH;
        if (v.kind === 'card') {
          var L = v.leg, out = H('div', 'qm-out', mapEl);
          out.innerHTML = '<div class="qm-ob"><span class="qm-ic">' + iconSvg('exit') + '</span><b>Exit ' + esc(B[L.fromBuilding].name) + '</b><span></span></div>' +
            '<div class="qm-walk">Walk outside<i></i><span>about ' + L.meters + ' m' + (L.say ? ' · ' + esc(L.say) : '') + '</span></div>' +
            '<div class="qm-ob"><span class="qm-ic">' + iconSvg('enter') + '</span><b>Enter ' + esc(B[L.toBuilding].name) + '</b><span></span></div>';
          fillCardLabels(out, L);
        } else {
          var svg = S('svg', { xmlns: SVGNS, width: '100%', height: '100%', role: 'img', 'aria-label': v.tab }, null);
          mapEl.appendChild(svg);
          if (v.kind === 'campus') drawCampus(svg, v, route, { w: w, h: h });
          else drawFloor(svg, v, route, { w: w, h: h }, opts);
          if (v.kind === 'floor') {
            var fr = FLOORS[v.fk];
            H('div', 'qm-chip', mapEl, esc(B[fr.b] ? B[fr.b].name : fr.b) + ' <span>· ' + esc(fr.label) + '</span>');
            var north = (B[fr.b] && B[fr.b].north) || 0;
            H('div', 'qm-compass', mapEl, '<svg viewBox="0 0 30 30"><g transform="rotate(' + north + ' 15 15)"><path d="M15 5l4 10h-8z" fill="#ea4335"/><path d="M15 25l-4-10h8z" fill="#c4c9cf"/></g><text x="15" y="' + (north % 360 === 0 ? 4.6 : 30) + '" font-size="0" fill="none">N</text></svg>');
          } else {
            H('div', 'qm-chip', mapEl, 'Campus <span>· walk outside</span>');
            H('div', 'qm-hint qm-walkchip', mapEl, '<span class="qm-dots"></span>Walk outside · about ' + v.leg.meters + ' m');
          }
          if (opts.edit && v.kind === 'floor') {
            H('div', 'qm-hint', mapEl, 'Click a hallway to move “You are here”');
            svg.addEventListener('click', function (ev) { pick(ev, svg, v); });
          }
        }
        tabs.forEach(function (tb, k) {
          tb.className = 'qm-tab' + (k === i ? ' on' : '');
          var pr = tb.querySelector('.qm-prog');
          if (pr) { pr.className = 'qm-prog'; if (k === i && timer) { void pr.offsetWidth; pr.className = 'qm-prog run'; } }
        });
        var firstOn = null;
        stepEls.forEach(function (el, k) {
          var on = route.steps[k].leg === i;
          el.className = 'qm-step' + (on ? ' on' : '') + (on && !firstOn ? ' cur' : '');
          if (on && !firstOn) firstOn = el;
        });
        if (firstOn && stepList && stepList.scrollHeight > stepList.clientHeight + 4) {
          var target = Math.max(0, firstOn.offsetTop - 8);
          if (stepList.scrollTo && shown) stepList.scrollTo({ top: target, behavior: 'smooth' }); else stepList.scrollTop = target;
        }
      }
      function fillCardLabels(out, L) {
        var spans = out.querySelectorAll('.qm-ob span:not(.qm-ic)');
        if (spans[0]) spans[0].textContent = cap(exitLabelFor(L));
        if (spans[1]) spans[1].textContent = cap(enterLabelFor(L));
      }
      function exitLabelFor(L) { var g = gidAt(L.fromBuilding, L.fromFloor, L.fromPoint); return g && N[g].ent ? entName(N[g].ent) : 'the doors'; }
      function enterLabelFor(L) { var g = gidAt(L.toBuilding, L.toFloor, L.toPoint); return g && N[g].ent ? entName(N[g].ent) : 'the doors'; }
      function pick(ev, svg, v) {
        var pt = svg.createSVGPoint(); pt.x = ev.clientX; pt.y = ev.clientY;
        var m = svg.getScreenCTM(); if (!m) return;
        var p = pt.matrixTransform(m.inverse()), fr = FLOORS[v.fk];
        var s = snap(fr.b, fr.level, p.x, p.y);
        if (!s) return;
        var d = setDesk({ building: fr.b, floor: fr.level, x: s.x, y: s.y });
        if (opts.onPick) opts.onPick(fr.level, Math.round(s.x * 10) / 10, Math.round(s.y * 10) / 10, { building: fr.b, node: d && d.node, desk: d });
        if (route && route.to) {
          var nr = QMapsApi.route(route.to.id, { avoidStairs: route.avoidStairs });
          if (nr) { render(container, nr, opts); return; }
        }
        v.pin = [s.x, s.y]; v.leg = null; v.full = true;
        show(cur);
      }
      function tick() {
        timer = null;
        if (dead || !root.isConnected) { dead = true; return; }
        var nx = (cur + 1) % views.length;
        timer = setTimeout(tick, nx === views.length - 1 ? interval * 1.4 : interval);
        show(nx);
      }
      function stop() { if (timer) clearTimeout(timer); timer = null; tabs.forEach(function (tb) { var pr = tb.querySelector('.qm-prog'); if (pr) pr.className = 'qm-prog'; }); }
      function destroy() { dead = true; stop(); if (root.parentNode) root.parentNode.removeChild(root); }
      if (views.length > 1 && opts.autoplay !== false && !opts.edit) timer = setTimeout(tick, interval);
      show(opts.start != null ? opts.start : 0);
      if (!views.length) H('div', 'qm-empty', mapEl, 'No map data loaded.');
      return { root: root, show: function (i) { stop(); show(i); }, stop: stop, destroy: destroy, views: views.length };
    }
    function gidAt(b, level, p) {
      var fr = FLOORS[b + '|' + level];
      if (!fr || !p) return null;
      for (var i = 0; i < fr.nodes.length; i++) { var n = N[fr.nodes[i]]; if (n && n.x === p[0] && n.y === p[1]) return n.gid; }
      return null;
    }
  
    /* ---------------------------------------------------------------- export */
    function info() {
      return BLIST.map(function (b) {
        return { building: b.code, name: b.name, floors: b.floors.map(function (f) { return { level: f.level, label: f.label, rooms: f.rooms.length, nodes: f.nodes.length }; }), entrances: b.entrances.map(function (e) { return e.id; }) };
      });
    }
    var QMapsApi = {
      load: load, find: find, route: route, render: render, setDesk: setDesk, getDesk: getDesk, snap: snap,
      parseQuery: parseQuery, config: config, info: info,
      _turn: function (a, b, c) { var d = turnDeg(a, b, c); return Math.abs(d) < 28 ? 'straight' : Math.abs(d) >= 150 ? 'uturn' : (Math.abs(d) < 55 ? 'slight-' : '') + (d > 0 ? 'right' : 'left'); }
    };
    return QMapsApi;
  })();
  

  var PHONE_URL_DEFAULT = 'https://cookiikid.github.io/front-desk/';
  var log = function () { console.log.apply(console, ['[Front Desk]'].concat([].slice.call(arguments))); };
  var sleep = function (ms) { return new Promise(function (r) { setTimeout(r, ms); }); };
  var digits = function (s) { return String(s || '').replace(/\D/g, ''); };
  var fmtPhone = function (d) { return d.length === 10 ? d.slice(0, 3) + '-' + d.slice(3, 6) + '-' + d.slice(6) : d; };
  var formatNote = function (cwid, rest) { return '[CWID]: ' + (cwid || '') + ' , [Notes]: ' + (rest || ''); };
  var store = {
    get: function (k, d) { try { var v = localStorage.getItem('qfd.' + k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set: function (k, v) { try { localStorage.setItem('qfd.' + k, JSON.stringify(v)); } catch (e) {} }
  };
  function cwidFrom(note) {
    if (!note) return null;
    var m = /\[CWID\]:\s*([a-z]{0,2}\d{7,9})/i.exec(note) || /[a-z]{0,2}\d{7,9}/i.exec(note);
    return m ? (m[1] || m[0]) : null;
  }
  function today() { var d = new Date(); return d.getFullYear() + '-' + (d.getMonth() + 1) + '-' + d.getDate(); }

  // ---------- watch Qless's "known consumer" lookup request ----------
  var lookupWaiters = [], lookupStarted = 0;
  var oOpen = XMLHttpRequest.prototype.open, oSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.open = function (method, url) {
    this._qfdLookup = /\/consumer(\?|$)/.test(String(url || '')) && /post/i.test(method);
    return oOpen.apply(this, arguments);
  };
  XMLHttpRequest.prototype.send = function () {
    if (this._qfdLookup) {
      lookupStarted = Date.now();
      this.addEventListener('loadend', function () {
        setTimeout(function () { var w = lookupWaiters; lookupWaiters = []; w.forEach(function (f) { f(true); }); onManualLookupDone(); }, 30);
      });
    }
    return oSend.apply(this, arguments);
  };
  function waitLookup(ms) {
    return new Promise(function (res) {
      lookupWaiters.push(res);
      setTimeout(function () { res(false); }, ms);
    });
  }

  function ready() { return window.vm && window.ko && vm.addConsumerVM && vm.selectedQueues && vm.toggleAddConsumer; }
  // Start after the whole script has run (setup link, constants), even when Qless is already loaded.
  setTimeout(function waitForQless() { if (ready()) init(); else setTimeout(waitForQless, 300); }, 0);

  var acvm, relay, pairing, currentLookup = null, last = null, remoteBusy = false, remoteAdding = false, panel, pill, toastBox, liveBox;
  var live = null, liveAt = 0, team = [], teamAt = 0, deskRelay = null;
  var ownName = ''; // a name the phone heard and we typed in (not a Qless lookup result)

  // One-time setup link: https://merchant.qless.com/cec/#qfd-setup=<base64url JSON {kbKey, me, dgKey}>
  function readSetupLink() {
    var m = /qfd-setup=([A-Za-z0-9_-]+)/.exec(location.hash);
    if (!m) return;
    try {
      var s = JSON.parse(atob(m[1].replace(/-/g, '+').replace(/_/g, '/')));
      if (s.kbKey) store.set('kbKey', s.kbKey);
      if (s.me) store.set('me', s.me);
      if (s.dgKey) store.set('dgKey', s.dgKey);
      if (s.desk) store.set('desk', s.desk);
      history.replaceState(null, '', location.pathname + location.search);
      setTimeout(function () { toast('✅ Front Desk setup saved'); }, 1500);
    } catch (e) { log('bad setup link', e); }
  }
  readSetupLink();

  function loadKb() {
    var key = store.get('kbKey', '');
    if (!key) return;
    fetch(phoneUrl() + 'kb.enc', { cache: 'no-cache' }).then(function (r) { return r.text(); })
      .then(function (t) { return QKB.decrypt(t, key); })
      .then(function (data) { QKB.load(data); log('knowledge base', QKB.version()); loadMaps(data.maps); renderLive(); })
      .catch(function (e) { log('knowledge base not loaded', e); });
  }
  // ---------- floor-plan maps with routes from the desk ----------
  var mapsOk = false, mapBox = null, mapCtl = null, mapShownFor = '', mapTimer = null, mapAutoAt = {};
  function loadMaps(m) {
    if (!m || !window.QMaps && typeof QMaps === 'undefined') return;
    try {
      QMaps.load({ buildings: m.buildings, campus: m.campus });
      var d = store.get('mapDesk', null);
      if (d) QMaps.setDesk(d);
      mapsOk = true; log('maps ready');
    } catch (e) { log('maps failed', e); }
  }
  function ensureMapBox() {
    if (mapBox) return mapBox;
    mapBox = document.createElement('div'); mapBox.id = 'qfd-map'; mapBox.hidden = true;
    mapBox.innerHTML = '<div class="mapc"></div>';
    document.body.appendChild(mapBox);
    return mapBox;
  }
  function hideMap() {
    clearTimeout(mapTimer);
    if (mapCtl) { try { mapCtl.destroy(); } catch (e) {} }
    mapCtl = null; mapShownFor = '';
    if (mapBox) mapBox.hidden = true;
  }
  // target: a map room id ("SC-ATRIUM1", "CC-201") or free text ("WSC 330", "the library")
  function showMap(target, auto) {
    if (!mapsOk || !target) return false;
    if (auto && (mapShownFor === target || Date.now() - (mapAutoAt[target] || 0) < 45000)) return false;
    var r = null;
    try { r = QMaps.route(target); } catch (e) { log('route failed', e); }
    if (!r) { if (!auto) toast('No route found on the map'); return false; }
    if (auto) mapAutoAt[target] = Date.now();
    ensureMapBox();
    if (mapCtl) { try { mapCtl.destroy(); } catch (e) {} }
    mapBox.hidden = false;
    mapCtl = QMaps.render(mapBox.querySelector('.mapc'), r, { onClose: hideMap });
    mapShownFor = target;
    toast('🗺 ' + (r.summary || 'Directions'));
    clearTimeout(mapTimer);
    mapTimer = setTimeout(hideMap, 90000);
    return true;
  }
  function editDesk() {
    if (!mapsOk) { toast('Maps not loaded yet'); return; }
    ensureMapBox(); hideMap(); mapBox.hidden = false;
    var d = QMaps.getDesk();
    mapCtl = QMaps.render(mapBox.querySelector('.mapc'), null, { edit: true, start: d, onClose: hideMap,
      onPick: function (floor, x, y, info) {
        var nd = QMaps.getDesk() || { floor: floor, x: x, y: y };
        store.set('mapDesk', { building: nd.building || (info && info.building) || 'CC', floor: nd.floor, x: nd.x, y: nd.y });
        toast('📍 Desk location saved');
      } });
  }
  function mapButton(c) { return c && c.map && mapsOk ? '<a href="#" class="mapbtn" data-map="' + esc(c.map) + '">🗺 Map</a>' : ''; }
  function wireMapButtons(root) {
    (root || document).querySelectorAll('[data-map]').forEach(function (a) {
      a.onclick = function (e) { e.preventDefault(); showMap(a.dataset.map, false); };
    });
  }

  function sendConfig() {
    if (!relay) return;
    var me = store.get('me', '');
    relay.send({ t: 'config', dgKey: store.get('dgKey', ''), kbKey: store.get('kbKey', ''), ignoreNames: me ? [me] : [] });
  }

  function init() {
    acvm = vm.addConsumerVM;
    log('ready');
    loadKb();
    installCwidAutofill();
    installAddCounter();
    installShortcuts();
    buildUi();
    startRelay();
    [vm.showAddConsumer, acvm.phone, acvm.consumerName, acvm.notes, acvm.queueIds, acvm.selectedTransactionType].forEach(function (o) {
      if (o && o.subscribe) o.subscribe(function () { publishState(); });
    });
    vm.showAddConsumer.subscribe(function (open) {
      if (!open) { currentLookup = null; return; }
      if (!remoteBusy) setTimeout(function () { focusEl('phoneInput'); }, 150);
    });
    setInterval(function () { publishState(); }, 30000);
  }

  // ---------- CWID auto-fill (what V5 did, via Knockout instead of a timer) ----------
  function installCwidAutofill() {
    // Lookup result arrives in consumerInfoWS.notes; Notes stays empty because auto-populate is off at Wylie.
    if (acvm.consumerInfoWS && acvm.consumerInfoWS.notes && acvm.consumerInfoWS.notes.subscribe) {
      acvm.consumerInfoWS.notes.subscribe(function (prev) {
        var id = cwidFrom(prev);
        if (!id || remoteBusy || !vm.showAddConsumer() || String(acvm.notes() || '').trim()) return;
        setTimeout(function () { if (!String(acvm.notes() || '').trim()) { acvm.notes(formatNote(id, '')); log('CWID filled', id); } }, 0);
      });
    }
    // Late name from the lookup -> tell the phone (it needs the name before it can auto-add).
    acvm.consumerName.subscribe(function (nm) {
      nm = String(nm || '').trim();
      if (nm && nm !== ownName && currentLookup && currentLookup.phone === digits(acvm.phone()) && !currentLookup.name) { currentLookup.name = nm; currentLookup.known = true; publishState(); }
    });
    acvm.notes.subscribe(function (v) {
      if (!v || remoteBusy) return;
      var prev = acvm.consumerInfoWS && ko.unwrap(acvm.consumerInfoWS.notes);
      if (prev && v === prev && !/^\[CWID\]:\s*\S*\s*,\s*\[Notes\]:\s*$/.test(v)) {
        var id = cwidFrom(v);
        if (id) setTimeout(function () { acvm.notes(formatNote(id, '')); log('CWID filled', id); }, 0);
      }
    });
  }
  // After typing a phone number by hand, jump to the end of Notes.
  function onManualLookupDone() {
    if (remoteBusy || !vm.showAddConsumer()) return;
    setTimeout(function () {
      var ta = formEl('addConsumerNotes');
      if (ta && document.activeElement && document.activeElement.id === 'phoneInput' && acvm.phoneIsValid()) {
        ta.focus(); ta.selectionStart = ta.selectionEnd = ta.value.length;
      }
    }, 120);
  }

  // ---------- daily counter (counts manual + phone adds; stores no student info) ----------
  function stats() {
    var s = store.get('stats', null);
    if (!s || s.date !== today()) s = { date: today(), total: 0, byQueue: {}, byService: {} };
    return s;
  }
  function describeForm() {
    var qid = acvm.queueIds()[0], q = vm.queuesWS && vm.queuesWS.getQueueById(Number(qid));
    var tt = (acvm.transactionTypes() || []).filter(function (t) { return String(t.id) === String(acvm.selectedTransactionType()); })[0];
    return {
      queue: q ? String(ko.unwrap(q.description)) : 'Queue',
      service: tt ? tt.description : '',
      name: String(acvm.consumerName() || '').trim()
    };
  }
  function waitAddResult() {
    return new Promise(function (res) {
      var t0 = Date.now(), sawEntering = false;
      (function poll() {
        if (!vm.showAddConsumer()) return res({ ok: true });
        if (acvm.showWarning && acvm.showWarning()) return res({ ok: false, msg: 'Qless is asking to confirm (queue not active) — answer on the PC' });
        if (acvm.isEnteringConsumer()) sawEntering = true;
        else if (sawEntering) return res({ ok: false, msg: 'Qless showed an error — check the PC' });
        if (Date.now() - t0 > 10000) return res({ ok: false, msg: 'Qless did not confirm the add' });
        setTimeout(poll, 150);
      })();
    });
  }
  function installAddCounter() {
    var orig = acvm.addCustomerToQueue;
    acvm.addCustomerToQueue = function () {
      var info = acvm.addButtonEnabled() ? describeForm() : null;
      var r = orig.apply(this, arguments);
      if (info) waitAddResult().then(function (res) {
        if (!res.ok) return;
        var s = stats();
        s.total++;
        s.byQueue[info.queue] = (s.byQueue[info.queue] || 0) + 1;
        var k = info.queue.replace(/^.*? - /, '') + ' · ' + (info.service || '—');
        s.byService[k] = (s.byService[k] || 0) + 1;
        store.set('stats', s);
        // Added from the PC keyboard while the phone was filling: tell the phone so it moves to the next student.
        if (!remoteAdding) last = { status: 'added', reqId: 'pc', ts: Date.now(), msg: 'Added ' + info.name + ' → ' + info.queue.replace(/^.*? - /, '') };
        renderPill(); publishState();
      });
      return r;
    };
  }

  // ---------- keyboard shortcuts ----------
  function openQueue(qid) {
    if (!vm.showAddConsumer()) vm.toggleAddConsumer(null, { target: { getAttribute: function () { return String(qid); } } });
    else acvm.queueIds([Number(qid)]);
  }
  function formEl(id) { return document.querySelector('#addConsumerContainer [id="' + id + '"]') || document.getElementById(id); }
  function focusEl(id) { var el = formEl(id); if (el && !el.disabled) el.focus(); }
  function installShortcuts() {
    document.addEventListener('keydown', function (e) {
      var typing = /INPUT|TEXTAREA|SELECT/.test((document.activeElement || {}).tagName || '');
      if ((e.ctrlKey && (e.key === 'k' || e.key === 'K')) || (e.key === '/' && !typing)) {
        var si = document.getElementById('qfd-search');
        if (si) { e.preventDefault(); if (liveBox.classList.contains('min')) { liveBox.classList.remove('min'); renderLive(); si = document.getElementById('qfd-search'); } si.focus(); si.select(); }
        return;
      }
      if (e.altKey && !e.ctrlKey && /^[1-9]$/.test(e.key)) {
        var q = vm.selectedQueues()[Number(e.key) - 1];
        if (q) { e.preventDefault(); openQueue(q.id); setTimeout(function () { focusEl('phoneInput'); }, 200); }
      } else if ((e.ctrlKey || e.altKey) && e.key === 'Enter' && vm.showAddConsumer()) {
        e.preventDefault(); acvm.addCustomerToQueue();
      } else if (e.key === 'Escape' && mapBox && !mapBox.hidden) {
        e.preventDefault(); hideMap();
      } else if (e.key === 'Escape' && live && live.countdown) {
        e.preventDefault(); relay.send({ t: 'cancel-auto' }); live.countdown = null; renderLive(); toast('⏸ Auto-add stopped');
      } else if (e.key === 'Escape' && vm.showAddConsumer() && !(acvm.showWarning && acvm.showWarning())) {
        acvm.cancelAddConsumer();
      }
    }, true);
  }

  // ---------- phone remote ----------
  function startRelay() {
    if (relay) relay.close();
    pairing = store.get('pairing', null);
    if (!pairing) { pairing = QRelay.newPairing(); store.set('pairing', pairing); }
    relay = new QRelay.Relay({
      topic: pairing.topic, key: pairing.key, role: 'pc',
      onMessage: onPhoneMessage,
      onStatus: function () { renderPill(); renderLive(); }
    });
    setTimeout(function () { publishState(true); }, 1500);
    startDesk();
    startKiosk();
  }
  // Who's available, from the Jabber helper running on this PC (desk/desk-agent.js).
  // Self check-in channel (students' phones -> this PC), also derived from the knowledge key.
  var kioskRelay = null, checkins = [];
  async function derivedPairing(name) {
    var k = store.get('kbKey', '');
    if (!k) return null;
    var h = async function (label) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label + '|' + k))); };
    var b64u = function (u) { var x = ''; u.forEach(function (c) { x += String.fromCharCode(c); }); return btoa(x).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
    return { topic: b64u((await h(name + '-topic')).slice(0, 12)), key: b64u(await h(name + '-key')) };
  }
  async function startKiosk() {
    var d = await derivedPairing('kiosk');
    if (!d || kioskRelay) return;
    kioskRelay = new QRelay.Relay({ topic: d.topic, key: d.key, role: 'pc', peer: 'kiosk', onMessage: onCheckin });
  }
  function onCheckin(m) {
    if (m.t !== 'checkin' || !/^\d{10}$/.test(m.phone || '')) return;
    if (checkins.some(function (c) { return c.phone === m.phone && Date.now() - c.at < 180000; })) return; // double taps
    checkins.push({ id: m.mid, at: Date.now(), queue: m.queue, service: m.service, phone: m.phone, name: String(m.name || '').slice(0, 60),
      cwid: String(m.cwid || '').replace(/[^a-z0-9]/gi, '').slice(0, 12), note: String(m.note || '').slice(0, 200), lang: m.lang });
    toast('📝 Self check-in: ' + m.name);
    chime();
    renderLive();
  }
  function chime() {
    try {
      var a = new (window.AudioContext || window.webkitAudioContext)(), o = a.createOscillator(), g = a.createGain();
      o.frequency.value = 880; g.gain.setValueAtTime(0.08, a.currentTime); g.gain.exponentialRampToValueAtTime(0.0001, a.currentTime + 0.35);
      o.connect(g); g.connect(a.destination); o.start(); o.stop(a.currentTime + 0.35);
    } catch (e) {}
  }
  function checkinToFill(c, add) {
    var q = vm.selectedQueues().filter(function (q) { return c.queue === 'finaid' ? /financ/i.test(ko.unwrap(q.description)) : /enroll/i.test(ko.unwrap(q.description)); })[0];
    var tt = q && (acvm.transactionTypesForQueueId(q.id) || []).filter(function (t) { return t.description.toLowerCase() === String(c.service).toLowerCase(); })[0];
    var note = (c.note || '') + (c.lang === 'es' ? (c.note ? ' ' : '') + '(Spanish)' : '');
    return { t: 'fill', reqId: 'kiosk-' + c.id, queueId: q ? q.id : null, serviceId: tt ? tt.id : null, phone: c.phone, name: c.name, cwid: c.cwid, note: note, add: add, manual: true };
  }
  function checkinsHtml() {
    if (!checkins.length) return '';
    return '<div class="team kiosk"><b>📝 Self check-ins (' + checkins.length + ')</b>' + checkins.map(function (c, i) {
      return '<div class="pp"><span class="pn">' + esc(c.name) + '</span><span class="pm">' + esc(fmtPhone(c.phone) + ' · ' + c.service + (c.cwid ? ' · ' + c.cwid : '') + (c.lang === 'es' ? ' · ES' : '')) + '</span>' +
        '<a href="#" data-ci="' + i + '" data-act="add">Add</a><a href="#" data-ci="' + i + '" data-act="fill">Fill</a><a href="#" data-ci="' + i + '" data-act="x" class="x">✕</a></div>' +
        (c.note ? '<div class="pm" style="padding-left:2px">“' + esc(c.note) + '”</div>' : '');
    }).join('') + '</div>';
  }
  function wireCheckins() {
    liveBox.querySelectorAll('[data-ci]').forEach(function (a) {
      a.onclick = function (e) {
        e.preventDefault();
        var c = checkins[Number(a.dataset.ci)];
        if (!c) return;
        if (a.dataset.act !== 'x') queueFill(checkinToFill(c, a.dataset.act === 'add'));
        checkins.splice(checkins.indexOf(c), 1);
        renderLive();
      };
    });
  }
  function kioskSignUrl() {
    return derivedPairing('kiosk').then(function (d) { return d ? phoneUrl() + 'sign.html#k=' + QRelay.encodePairing(d) : null; });
  }

  async function deskPairing() {
    var d = store.get('desk', null), k = store.get('kbKey', '');
    if (d || !k) return d;
    var h = async function (label) { return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label + '|' + k))); };
    var b64u = function (u) { var x = ''; u.forEach(function (c) { x += String.fromCharCode(c); }); return btoa(x).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
    return { topic: b64u((await h('desk-topic')).slice(0, 12)), key: b64u(await h('desk-key')) };
  }
  async function startDesk() {
    var d = await deskPairing();
    if (!d || deskRelay) return;
    deskRelay = new QRelay.Relay({
      topic: d.topic, key: d.key, role: 'pc', peer: 'desk',
      onMessage: function (m) { if (m.t === 'presence') { team = m.people || []; teamAt = Date.now(); renderLive(); if (panel && !panel.hidden) renderPanel(); } }
    });
  }
  function autoFillOn() { return store.get('autoFill', true); }
  function autoAddOn() { return store.get('autoAdd', true); }
  function onPhoneMessage(m) {
    if (m.t === 'hello') { publishState(true); sendConfig(); }
    else if (m.t === 'fill') {
      if (!autoFillOn() && !m.manual) return; // switched off on the PC: captions/tips only
      if (m.add && m.auto && !autoAddOn()) m.add = false;
      queueFill(m);
    }
    else if (m.t === 'live') { live = m; liveAt = Date.now(); renderLive(); }
    else if (m.t === 'cancel') { if (vm.showAddConsumer()) acvm.cancelAddConsumer(); currentLookup = null; live = null; hideMap(); renderLive(); publishState(); }
  }

  var pendingFill = null, filling = false;
  function queueFill(f) {
    pendingFill = pendingFill ? Object.assign(pendingFill, f) : f;
    if (filling) return;
    filling = true;
    (function next() {
      var f = pendingFill; pendingFill = null;
      if (!f) { filling = false; return; }
      remoteBusy = true;
      applyFill(f).catch(function (err) {
        log('fill failed', err);
        setLast({ status: 'error', msg: 'PC error: ' + err.message, reqId: f.reqId });
      }).then(function () { remoteBusy = false; publishState(); next(); });
    })();
  }

  async function setPhone(d) {
    acvm.consumerName(''); acvm.notes('');
    try { acvm.consumerInfoWS.notes(null); acvm.consumerInfoWS.consumerName = null; } catch (e) {}
    var started = lookupStarted, done = waitLookup(4000);
    var input = formEl('phoneInput');
    if (input) {
      input.value = d;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: d.slice(-1), keyCode: 48 + Number(d.slice(-1)) }));
    }
    await sleep(60);
    if (lookupStarted === started) { // Qless's own handler didn't fire — do it directly
      if (!acvm.phoneIsValid()) acvm.phone(fmtPhone(d));
      acvm.checkForKnownConsumer();
    }
    return done;
  }

  async function applyFill(f) {
    var qid = f.queueId != null ? Number(f.queueId) : null;
    if (!vm.showAddConsumer()) {
      openQueue(qid || vm.selectedQueues()[0].id);
      await waitFor(function () { var el = formEl('phoneInput'); return vm.showAddConsumer() && el && el.offsetParent; }, 600);
    } else if (qid && !(acvm.queueIds().length === 1 && Number(acvm.queueIds()[0]) === qid)) {
      acvm.queueIds([qid]);
    }
    if (f.serviceId != null) await waitFor(function () { return hasService(f.serviceId); }, 300);
    if (f.serviceId != null) {
      var tt = (acvm.transactionTypes() || []).filter(function (t) { return String(t.id) === String(f.serviceId); })[0];
      if (tt) acvm.selectedTransactionType(tt.id);
    }
    var lk = currentLookup;
    if (f.phone && f.phone.length === 10 && (digits(acvm.phone()) !== f.phone || !lk || lk.phone !== f.phone)) {
      toast('📱 Looking up ' + fmtPhone(f.phone) + '…');
      var looked = await setPhone(f.phone);
      if (looked) await waitFor(function () { return String(acvm.consumerName() || '').trim() || ko.unwrap(acvm.consumerInfoWS.notes); }, 1500);
      var prev = acvm.consumerInfoWS && ko.unwrap(acvm.consumerInfoWS.notes);
      var nm = String(acvm.consumerName() || '').trim();
      currentLookup = lk = { phone: f.phone, name: nm, cwid: cwidFrom(prev), known: !!(nm || prev) };
      await sleep(120);
    }
    if (f.name && !String(acvm.consumerName() || '').trim()) { ownName = f.name; acvm.consumerName(f.name); }
    var cwid = f.cwid || (lk && lk.phone === f.phone ? lk.cwid : null);
    var note = cwid || f.note ? formatNote(cwid, f.note) : lk && lk.phone === f.phone && !acvm.notes() ? formatNote('', '') : null;
    if (note) {
      acvm.notes(note);
      // If the old V5 script is still enabled it rewrites Notes ~400 ms after the lookup — put ours back.
      setTimeout(function () { if (vm.showAddConsumer() && acvm.notes() !== note && /^\[CWID\]: \S* , \[Notes\]: $/.test(acvm.notes() || '')) acvm.notes(note); }, 500);
    }
    publishState();
    if (f.add) await doAdd(f.reqId);
    else toast('📱 Filled from iPhone');
  }

  async function doAdd(reqId) {
    if (!acvm.addButtonEnabled()) {
      var why = !acvm.phoneIsValid() ? 'Phone number is not valid' :
        !String(acvm.consumerName() || '').trim() ? 'Name needed — they\'re new; say or type their name' : 'Form incomplete on the PC';
      setLast({ status: 'error', msg: why, reqId: reqId });
      toast('⚠️ ' + why);
      return;
    }
    var info = describeForm();
    remoteAdding = true;
    acvm.addCustomerToQueue();
    var res = await waitAddResult();
    remoteAdding = false;
    if (res.ok) {
      var msg = 'Added ' + info.name + ' → ' + info.queue.replace(/^.*? - /, '') + (info.service ? ' · ' + info.service : '');
      setLast({ status: 'added', msg: msg, reqId: reqId });
      toast('✅ ' + msg);
    } else {
      setLast({ status: 'error', msg: res.msg, reqId: reqId });
      toast('⚠️ ' + res.msg);
    }
  }
  function setLast(l) { l.ts = Date.now(); last = l; publishState(); }
  function hasService(id) { return (acvm.transactionTypes() || []).some(function (t) { return String(t.id) === String(id); }); }
  function waitFor(cond, ms) {
    return new Promise(function (res) {
      var t0 = Date.now();
      (function poll() { if (cond()) return res(true); if (Date.now() - t0 > ms) return res(false); setTimeout(poll, 25); })();
    });
  }

  function queuedCount(qid) {
    var el = document.getElementById(String(qid));
    var m = el && /Queued[^()]*\((\d+)\)/.exec(el.textContent.replace(/\s+/g, ' '));
    return m ? Number(m[1]) : null;
  }
  function buildState() {
    var open = !!vm.showAddConsumer();
    var s = stats();
    return {
      t: 'state',
      queues: vm.selectedQueues().map(function (q) {
        var w = ''; try { w = String(ko.unwrap(q.waitTime) || ''); } catch (e) {}
        return {
          id: q.id, name: String(ko.unwrap(q.description)), wait: w, waiting: queuedCount(q.id),
          services: (acvm.transactionTypesForQueueId(q.id) || []).map(function (t) { return { id: t.id, name: t.description }; })
        };
      }),
      modal: open ? {
        queueId: acvm.queueIds()[0], serviceId: acvm.selectedTransactionType(), phone: digits(acvm.phone()),
        name: String(acvm.consumerName() || ''), notes: String(acvm.notes() || '').slice(0, 300), canAdd: !!acvm.addButtonEnabled()
      } : null,
      lookup: currentLookup, last: last, autoFill: autoFillOn(), autoAdd: autoAddOn(),
      stats: { total: s.total, byQueue: s.byQueue }
    };
  }
  var pubTimer = null;
  function publishState(now) {
    clearTimeout(pubTimer);
    pubTimer = setTimeout(function () {
      if (!relay) return;
      try { relay.send(buildState(), true); } catch (e) { log('state error', e); }
    }, now ? 0 : 300);
  }

  // ---------- on-screen bits ----------
  function phoneUrl() { return store.get('phoneUrl', PHONE_URL_DEFAULT); }
  function pairLink() { return phoneUrl() + '#p=' + QRelay.encodePairing(pairing); }

  function buildUi() {
    var css = document.createElement('style');
    css.textContent = [
      '#qfd-pill{position:fixed;right:10px;bottom:30px;z-index:99999;background:#fff;border:1px solid #c9c9c9;border-radius:16px;padding:5px 12px;font:13px/1.2 Arial,sans-serif;color:#333;box-shadow:0 2px 6px rgba(0,0,0,.15);cursor:pointer;user-select:none}',
      '#qfd-pill .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;background:#bbb;vertical-align:middle}',
      '#qfd-pill .dot.on{background:#2db34a}#qfd-pill .dot.half{background:#e8a317}',
      '#qfd-panel{position:fixed;right:10px;bottom:64px;z-index:99999;width:330px;max-height:80vh;overflow:auto;background:#fff;border:1px solid #c9c9c9;border-radius:8px;box-shadow:0 6px 24px rgba(0,0,0,.2);font:13px/1.4 Arial,sans-serif;color:#333}',
      '#qfd-panel h3{margin:0;padding:10px 12px;background:#f0f0f0;font-size:14px;display:flex;justify-content:space-between;align-items:center}',
      '#qfd-panel section{padding:10px 12px;border-top:1px solid #eee}',
      '#qfd-panel h4{margin:0 0 6px;font-size:12px;text-transform:uppercase;color:#888;letter-spacing:.04em}',
      '#qfd-panel button{background:#1a9ad6;color:#fff;border:0;border-radius:4px;padding:6px 10px;cursor:pointer;font-size:12px;margin:2px 4px 2px 0}',
      '#qfd-panel button.grey{background:#999}',
      '#qfd-panel input{width:100%;box-sizing:border-box;padding:5px;font-size:12px;border:1px solid #ccc;border-radius:4px}',
      '#qfd-panel table{width:100%;border-collapse:collapse}#qfd-panel td{padding:2px 0}#qfd-panel td:last-child{text-align:right;font-weight:bold}',
      '#qfd-panel kbd{background:#eee;border:1px solid #ccc;border-radius:3px;padding:0 4px;font-size:11px}',
      '#qfd-qr{display:flex;justify-content:center;padding:8px 0}#qfd-qr img,#qfd-qr canvas{width:200px;height:200px}',
      '#qfd-link{word-break:break-all;font-size:11px;color:#666}',
      '#qfd-toasts{position:fixed;bottom:66px;left:14px;z-index:100000;display:flex;flex-direction:column;gap:6px;align-items:flex-start}',
      '#qfd-live{position:fixed;top:136px;right:14px;z-index:99998;width:390px;max-height:calc(100vh - 210px);overflow:auto;background:#fff;border:1px solid #c9c9c9;border-radius:10px;box-shadow:0 6px 24px rgba(0,0,0,.18);font:13px/1.4 Arial,sans-serif;color:#222}',
      '#qfd-live .hd{display:flex;align-items:center;gap:8px;padding:8px 12px;background:#f3f6f8;border-bottom:1px solid #e3e6ea;font-weight:bold;cursor:pointer}',
      '#qfd-live .hd .dot{width:9px;height:9px;border-radius:50%;background:#bbb}#qfd-live .hd .dot.on{background:#e5484d;animation:qfdp 1.2s infinite}',
      '@keyframes qfdp{50%{opacity:.35}}',
      '#qfd-live .lang{background:#1a9ad6;color:#fff;border-radius:8px;padding:1px 7px;font-size:11px}',
      '#qfd-live .cap{padding:8px 12px;color:#666;font-size:13px;max-height:66px;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end}',
      '#qfd-live .cap b{color:#111;font-weight:normal}',
      '#qfd-live .flds{display:flex;flex-wrap:wrap;gap:5px;padding:0 12px 8px}',
      '#qfd-live .flds span{background:#eef1f4;border-radius:10px;padding:2px 8px;font-size:12px}#qfd-live .flds span.miss{color:#a0a6ad}',
      '#qfd-live .cd{margin:0 12px 8px;padding:9px 12px;border-radius:8px;background:#c27c0e;color:#fff;font-size:15px;font-weight:bold}',
      '#qfd-live .lk{margin:0 12px 8px;padding:7px 10px;border-radius:8px;font-size:13px}#qfd-live .lk.known{background:#e5f5eb;color:#1f7a40}#qfd-live .lk.new{background:#fbf0dc;color:#8a5a08}',
      '#qfd-live .tip{margin:0 12px 10px;padding:9px 11px;border-radius:8px;background:#fff8e6;border:1px solid #f0d9a0}',
      '#qfd-live .tip b{display:block;margin-bottom:3px;font-size:13.5px}#qfd-live .tip .say{font-size:14px;color:#111}',
      '#qfd-live .tip.place{background:#e8f4fb;border-color:#a9d4ee}#qfd-live .tip.place .say{font-size:15px;font-weight:bold}',
      '#qfd-live .tip ul{margin:5px 0 0;padding-left:17px;color:#555;font-size:12.5px}',
      '#qfd-live .up{padding:6px 12px 10px;color:#666;font-size:12px;border-top:1px solid #eee}#qfd-live .up div{padding:1px 0}',
      '#qfd-live.min .body{display:none}',
      '#qfd-live .sw{display:flex;gap:6px;align-items:center;padding:8px 12px 0}',
      '#qfd-live .kiosk{background:#eef7ee;border-color:#bfe0c2}#qfd-live .kiosk a.x{background:#aaa}',
      '#qfd-live a.mapbtn{float:right;text-decoration:none;background:#1a73e8;color:#fff;border-radius:12px;padding:1px 9px;font-size:12px;font-weight:normal}',
      '#qfd-map{position:fixed;left:24px;top:96px;z-index:100001;width:min(760px,calc(100vw - 460px));min-width:560px}',
      '#qfd-map .mapc{border-radius:18px;overflow:hidden;box-shadow:0 18px 60px rgba(0,0,0,.35)}',
      '#qfd-live .sw button{border:1px solid #c9c9c9;background:#f1f1f1;color:#666;border-radius:14px;padding:4px 10px;font:bold 12px Arial,sans-serif;cursor:pointer}',
      '#qfd-live .sw button.on{background:#2db34a;border-color:#2db34a;color:#fff}',
      '#qfd-live .sw .phone-st{margin-left:auto;color:#888;font-size:12px}',
      '#qfd-live .srch{padding:8px 12px}',
      '#qfd-live .srch input{width:100%;box-sizing:border-box;padding:8px 10px;border:1px solid #c9d3dc;border-radius:8px;font:14px Arial,sans-serif;outline:none}',
      '#qfd-live .srch input:focus{border-color:#1a9ad6;box-shadow:0 0 0 3px rgba(26,154,214,.15)}',
      '#qfd-live .team{margin:0 12px 10px;padding:8px 10px;border-radius:8px;background:#f5f7f9;border:1px solid #e3e6ea}',
      '#qfd-live .pp,#qfd-panel .pp{display:flex;align-items:center;gap:6px;padding:3px 0}',
      '.pp .pd{width:8px;height:8px;border-radius:50%;flex:0 0 8px}.pp .pn{font-weight:bold}.pp .pm{color:#888;font-size:12px;flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}',
      '.pp a,#qfd-live a.boss{text-decoration:none;background:#1a9ad6;color:#fff;border-radius:6px;padding:1px 7px;font-size:12px;font-weight:normal}',
      '.qfd-toast{background:#333;color:#fff;padding:8px 12px;border-radius:6px;font:13px Arial,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.25);transition:opacity .4s}'
    ].join('\n');
    document.head.appendChild(css);
    pill = document.createElement('div'); pill.id = 'qfd-pill'; pill.title = 'Front Desk Assistant';
    pill.onclick = function () { panel.hidden = !panel.hidden; if (!panel.hidden) renderPanel(); };
    toastBox = document.createElement('div'); toastBox.id = 'qfd-toasts';
    panel = document.createElement('div'); panel.id = 'qfd-panel'; panel.hidden = true;
    liveBox = document.createElement('div'); liveBox.id = 'qfd-live'; liveBox.hidden = true;
    if (store.get('liveMin', false)) liveBox.classList.add('min');
    document.body.appendChild(pill); document.body.appendChild(panel); document.body.appendChild(toastBox); document.body.appendChild(liveBox);
    renderPill();
    setInterval(renderLive, 5000);
  }
  function renderPill() {
    if (!pill) return;
    var st = relay ? relay.status() : { brokers: 0, peerOnline: false };
    var cls = st.peerOnline ? 'on' : st.brokers ? 'half' : '';
    var txt = st.peerOnline ? 'iPhone connected' : st.brokers ? 'iPhone offline' : 'Relay offline';
    pill.innerHTML = '<span class="dot ' + cls + '"></span>' + txt + ' · Today: <b>' + stats().total + '</b>';
    if (panel && !panel.hidden) renderPanel();
  }
  function esc(s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function renderPanel() {
    var s = stats(), st = relay.status();
    var rows = Object.keys(s.byService).sort().map(function (k) { return '<tr><td>' + esc(k) + '</td><td>' + s.byService[k] + '</td></tr>'; }).join('');
    var qs = vm.selectedQueues().map(function (q, i) { return '<div><kbd>Alt+' + (i + 1) + '</kbd> Add Student – ' + esc(ko.unwrap(q.description)) + '</div>'; }).join('');
    panel.innerHTML =
      '<h3>Front Desk Assistant <button class="grey" id="qfd-close">✕</button></h3>' +
      '<section><h4>iPhone</h4><div>' + (st.peerOnline ? '🟢 iPhone connected' : '⚪ iPhone not connected') + ' · relay ' + st.brokers + '/2</div>' +
      '<div style="margin-top:6px"><button id="qfd-pair">Show pairing QR</button><button class="grey" id="qfd-repair">New key</button></div>' +
      '<div id="qfd-pairbox" hidden><div id="qfd-qr"></div><div id="qfd-link"></div>' +
      '<div style="font-size:11px;color:#888;margin-top:4px">Scan with the iPhone camera, open in Safari. Anyone with this link can fill this form — keep it private.</div></div></section>' +
      teamPanelHtml() +
      '<section><h4>Today · ' + s.total + ' students</h4><table>' + (rows || '<tr><td style="color:#999">Nobody yet</td><td></td></tr>') + '</table>' +
      '<div style="margin-top:6px"><button class="grey" id="qfd-reset">Reset today</button></div></section>' +
      '<section><h4>Shortcuts</h4>' + qs + '<div><kbd>Ctrl+Enter</kbd> Add (submit)</div><div><kbd>Esc</kbd> Stop the auto-add countdown / close the form</div>' +
      '<div style="color:#888;font-size:11px;margin-top:4px">Phone field is focused automatically; after the lookup the cursor jumps to Notes.</div></section>' +
      '<section><h4>Busy? Self check-in</h4><div style="font-size:12px;color:#666;margin-bottom:6px">Print the QR sign for the counter. Students check themselves in on their phone; they show up here with an Add button.</div>' +
      '<button id="qfd-sign">Open the printable QR sign</button></section>' +
      '<section><h4>Maps</h4><div style="font-size:12px;color:#666;margin-bottom:6px">Routes start at your desk. If the green "You are here" pin is off, click Set and then click your exact spot.</div>' +
      '<button id="qfd-desk">Set my desk on the map</button> <button class="grey" id="qfd-maptest">Test: route to TSI</button></section>' +
      '<section><h4>Setup</h4>' +
      '<div style="margin-bottom:6px">Deepgram key (speech AI)<input id="qfd-dg" type="password" value="' + esc(store.get('dgKey', '')) + '" placeholder="paste key"></div>' +
      '<div style="margin-bottom:6px">Your name (so it never mistakes you for the student)<input id="qfd-me" value="' + esc(store.get('me', '')) + '"></div>' +
      '<div style="font-size:12px;color:#666">Knowledge base: ' + (QKB.loaded() ? '✅ ' + esc(QKB.version()) : store.get('kbKey', '') ? '⏳ loading / failed' : '❌ no key — open your setup link') + '</div></section>' +
      '<section><h4>Phone app address</h4><input id="qfd-url" value="' + esc(phoneUrl()) + '"></section>';
    panel.querySelector('#qfd-close').onclick = function () { panel.hidden = true; };
    panel.querySelector('#qfd-pair').onclick = showQr;
    panel.querySelector('#qfd-desk').onclick = function () { panel.hidden = true; editDesk(); };
    panel.querySelector('#qfd-maptest').onclick = function () { panel.hidden = true; showMap('CC-201', false); };
    panel.querySelector('#qfd-sign').onclick = function () { kioskSignUrl().then(function (u) { if (u) window.open(u, '_blank'); else toast('Open your setup link first'); }); };
    panel.querySelector('#qfd-repair').onclick = function () {
      pairing = QRelay.newPairing(); store.set('pairing', pairing); startRelay(); renderPanel(); showQr();
    };
    panel.querySelector('#qfd-reset').onclick = function () { store.set('stats', null); renderPill(); };
    panel.querySelector('#qfd-url').onchange = function (e) { store.set('phoneUrl', e.target.value.trim()); };
    panel.querySelector('#qfd-dg').onchange = function (e) { store.set('dgKey', e.target.value.trim()); sendConfig(); toast('Sent to iPhone'); };
    panel.querySelector('#qfd-me').onchange = function (e) { store.set('me', e.target.value.trim()); sendConfig(); };
  }
  // ---------- live assistant overlay (captions, detected fields, countdown, tips) ----------
  var searchQuery = '';
  // Typed search: knowledge cards, places + directions, any room number, staff, Jabber people.
  function renderSearch() {
    var box = liveBox && liveBox.querySelector('#qfd-results');
    if (!box) return;
    var q = (searchQuery || '').trim();
    if (!q) { box.innerHTML = ''; return; }
    var h = '', cards = QKB.loaded() ? QKB.search(q, 6) : [];
    cards.forEach(function (c) {
      h += '<div class="tip' + (c.kind === 'place' ? ' place' : '') + '"><b>' + ({ staff: '👤 ', place: '📍 ' }[c.kind] || '💡 ') + esc(c.title) + mapButton(c) + '</b>' + (c.say ? '<div class="say">' + esc(c.say) + '</div>' : '') +
        (c.facts.length ? '<ul>' + c.facts.slice(0, 4).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
    });
    var ql = q.toLowerCase();
    var people = team.filter(function (p) { return (p.name + ' ' + p.groups.join(' ') + ' ' + (p.title || '')).toLowerCase().indexOf(ql) >= 0; }).slice(0, 6);
    if (people.length) h += '<div class="team"><b>Jabber</b>' + people.map(personRow).join('') + '</div>';
    if (mapsOk && !cards.some(function (c) { return c.map; })) {
      var f = null; try { f = QMaps.find(q); } catch (e) {}
      if (f) h = '<div class="tip place"><b>📍 ' + esc(f.label || f.id) + '<a href="#" class="mapbtn" data-map="' + esc(f.id) + '">🗺 Map</a></b></div>' + h;
    }
    box.innerHTML = h || '<div class="up">No matches.</div>';
    wireMapButtons(box);
  }
  var STATE_DOT = { available: '#2db34a', busy: '#e5484d', away: '#e8a317', offline: '#bbb' };
  var STATE_RANK = { available: 0, away: 1, busy: 2, offline: 3 };
  function groupsFor(tips) {
    var q = live && live.fields && live.fields.queueId != null && vm.queuesWS && vm.queuesWS.getQueueById(Number(live.fields.queueId));
    var qn = q ? String(ko.unwrap(q.description)) : '', text = (live && live.text || '').toLowerCase(), g = [];
    var ids = (tips || []).map(function (c) { return c.id + ' ' + c.title; }).join(' ').toLowerCase();
    if (/veteran|gi bill|hazlewood|\bva\b/.test(text + ids)) g.push('Veterans');
    if (/financ/i.test(qn) || /fafsa|financial aid|refund|scholarship|verification/.test(ids)) g.push('Financial Aid');
    if (/testing|tsi|placement/.test(ids + text)) g.push('Testing');
    if (/registrar|transcript|residency|graduat/.test(ids)) g.push('Registrar');
    if (/access|disabilit|counsel/.test(ids + text)) g.push('Access, Counseling, Dean of Students');
    if (/career/.test(ids + text)) g.push('Career Center');
    if (/police|emergency/.test(ids + text)) g.push('Police');
    if (/enroll/i.test(qn) || /advis|degree plan|hold/.test(ids + text) || !g.length) g.push('Advising');
    return g;
  }
  function personRow(p) {
    var call = p.ext ? '<a href="ciscotel:' + esc(p.ext) + '" title="Call ' + esc(p.name) + ' in Jabber">📞 ' + esc(p.ext) + '</a>' : '';
    var im = '<a href="ciscoim:' + esc(p.jid) + '" title="Message ' + esc(p.name) + ' in Jabber">💬</a>';
    return '<div class="pp"><span class="pd" style="background:' + (STATE_DOT[p.state] || '#bbb') + '"></span><span class="pn">' + esc(p.name) + '</span>' +
      '<span class="pm">' + esc(p.msg && p.msg !== '@' + p.ext ? p.msg : p.state === 'available' ? '' : p.state) + '</span>' + call + im + '</div>';
  }
  function teamHtml(tips) {
    if (!team.length) return '';
    var groups = groupsFor(tips), h = '';
    groups.slice(0, 2).forEach(function (g) {
      var list = team.filter(function (p) { return p.groups.indexOf(g) >= 0; })
        .sort(function (a, b) { return STATE_RANK[a.state] - STATE_RANK[b.state] || a.name.localeCompare(b.name); });
      if (!list.length) return;
      var free = list.filter(function (p) { return p.state === 'available'; }).length;
      var shown = list.filter(function (p) { return p.state !== 'offline'; }).slice(0, 5);
      h += '<div class="team"><b>' + esc(g) + '</b> <span style="color:#888">· ' + free + ' available</span>' + shown.map(personRow).join('') + '</div>';
    });
    return h;
  }
  function bossLink() {
    var b = team.filter(function (p) { return /alicia phillips/i.test(p.name); })[0];
    return b ? '<a class="boss" href="ciscoim:' + esc(b.jid) + '" title="Message ' + esc(b.name) + ' in Jabber" onclick="event.stopPropagation()">💬 Alicia</a>' : '';
  }
  var LANG_NAMES = { es: 'Spanish', fr: 'French', de: 'German', hi: 'Hindi', ru: 'Russian', pt: 'Portuguese', ja: 'Japanese', it: 'Italian', nl: 'Dutch', vi: 'Vietnamese', zh: 'Chinese', ko: 'Korean', ar: 'Arabic' };
  function renderLive() {
    if (!liveBox) return;
    var st = relay ? relay.status() : { peerOnline: false };
    var fresh = live && Date.now() - liveAt < 60000;
    liveBox.hidden = false;
    var keepSearch = liveBox.querySelector('#qfd-search'), q = keepSearch ? keepSearch.value : searchQuery, hadFocus = keepSearch && document.activeElement === keepSearch;
    var speaking = live && Date.now() - liveAt < 4000 && live.text;
    var h = '<div class="hd" id="qfd-live-hd"><span class="dot' + (speaking ? ' on' : '') + '"></span>' +
      (speaking ? 'Listening' : 'iPhone ready') +
      (live && live.lang && live.lang !== 'en' ? ' <span class="lang">🌐 ' + esc(LANG_NAMES[live.lang] || live.lang) + '</span>' : '') +
      '<span style="margin-left:auto;font-weight:normal;color:#888;display:flex;gap:6px;align-items:center">' + bossLink() + ' ' + (liveBox.classList.contains('min') ? '▸' : '▾') + '</span></div>' +
      '<div class="body"><div class="sw">' +
      '<button id="qfd-sw-fill" class="' + (autoFillOn() ? 'on' : '') + '" title="Let the iPhone open and fill the form">Auto-fill ' + (autoFillOn() ? 'ON' : 'OFF') + '</button>' +
      '<button id="qfd-sw-add" class="' + (autoAddOn() ? 'on' : '') + '" title="Let the countdown add students by itself">Auto-add ' + (autoAddOn() ? 'ON' : 'OFF') + '</button>' +
      '<span class="phone-st">' + (st.peerOnline ? '📱 on' : '📱 off') + '</span></div>' +
      '<div class="srch"><input id="qfd-search" placeholder="Search anything… (room, office, FAFSA, a person)  — Ctrl+K" autocomplete="off"></div><div id="qfd-results"></div>' + checkinsHtml();
    if (live && live.text) {
      var words = live.text.split(/\s+/), cut = Math.max(0, words.length - 14);
      h += '<div class="cap"><div>' + esc(words.slice(0, cut).join(' ')) + ' <b>' + esc(words.slice(cut).join(' ')) + '</b></div></div>';
    }
    if (live && live.fields) {
      var f = live.fields, q = f.queueId != null && vm.queuesWS && vm.queuesWS.getQueueById(Number(f.queueId));
      var tt = q && (acvm.transactionTypesForQueueId(q.id) || []).filter(function (t) { return String(t.id) === String(f.serviceId); })[0];
      var chip = function (v, label) { return '<span' + (v ? '' : ' class="miss"') + '>' + esc(v || label) + '</span>'; };
      h += '<div class="flds">' + chip(q && String(ko.unwrap(q.description)).replace(/^.*? - /, ''), 'queue?') + chip(tt && tt.description, 'service?') +
        chip(f.phone && fmtPhone(f.phone), 'phone?') + chip(f.name || (currentLookup && currentLookup.name), 'name?') +
        chip(f.cwid || (currentLookup && currentLookup.cwid), 'CWID?') + '</div>';
    }
    if (currentLookup) {
      h += '<div class="lk ' + (currentLookup.known ? 'known' : 'new') + '">' + (currentLookup.known ?
        '↩︎ Returning: ' + esc(currentLookup.name || 'name on file') + (currentLookup.cwid ? ' · CWID ' + esc(currentLookup.cwid) : ' · ask for CWID') :
        (live && live.fields && live.fields.name && live.fields.cwid ? '★ New student — name + CWID captured' : '★ New number — get their name and CWID')) + '</div>';
    }
    if (live && live.countdown) h += '<div class="cd">Adding in ' + live.countdown + '… &nbsp;<span style="font-weight:normal">Esc or say "stop" to cancel</span></div>';
    var tips = (live && live.tips || []).map(function (id) { return QKB.byId(id); }).filter(Boolean);
    tips.forEach(function (c) {
      h += '<div class="tip' + (c.kind === 'place' ? ' place' : '') + '"><b>' + ({ staff: '👤 ', place: '📍 ' }[c.kind] || '💡 ') + esc(c.title) + mapButton(c) + '</b>' + (c.say ? '<div class="say">' + esc(c.say) + '</div>' : '') +
        (c.facts.length ? '<ul>' + c.facts.slice(0, 4).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
    });
    // "where is…" -> the map pops up by itself
    if (tips[0] && tips[0].kind === 'place' && tips[0].map && live && Date.now() - liveAt < 15000) showMap(tips[0].map, true);
    h += teamHtml(tips);
    var up = QKB.loaded() ? QKB.upcoming(14) : [];
    if (up.length && !tips.length) h += '<div class="up"><b>Coming up</b>' + up.slice(0, 4).map(function (d) { return '<div>' + esc(QKB.fmtDate(d.date)) + ' — ' + esc(d.label) + '</div>'; }).join('') + '</div>';
    h += '</div>';
    liveBox.innerHTML = h;
    liveBox.querySelector('#qfd-live-hd').onclick = function () { liveBox.classList.toggle('min'); store.set('liveMin', liveBox.classList.contains('min')); renderLive(); };
    liveBox.querySelector('#qfd-sw-fill').onclick = function () { store.set('autoFill', !autoFillOn()); toast('Auto-fill ' + (autoFillOn() ? 'ON' : 'OFF')); publishState(true); renderLive(); };
    liveBox.querySelector('#qfd-sw-add').onclick = function () { store.set('autoAdd', !autoAddOn()); toast('Auto-add ' + (autoAddOn() ? 'ON' : 'OFF')); if (!autoAddOn() && relay) relay.send({ t: 'cancel-auto' }); publishState(true); renderLive(); };
    var si = liveBox.querySelector('#qfd-search');
    si.value = q || '';
    si.oninput = function () { searchQuery = si.value; renderSearch(); };
    si.onkeydown = function (e) {
      if (e.key === 'Escape') { si.value = ''; searchQuery = ''; renderSearch(); si.blur(); }
      if (e.key === 'Enter') { var m = liveBox.querySelector('#qfd-results [data-map]'); if (m) showMap(m.dataset.map, false); }
      e.stopPropagation();
    };
    if (hadFocus) { si.focus(); si.selectionStart = si.selectionEnd = si.value.length; }
    renderSearch();
    wireCheckins();
    wireMapButtons(liveBox);
  }

  function teamPanelHtml() {
    if (!team.length) return '<section><h4>Jabber</h4><div style="color:#888">Jabber helper not connected — it starts with Windows (desk\\start-hidden.vbs).</div></section>';
    var groups = [];
    team.forEach(function (p) { p.groups.forEach(function (g) { if (groups.indexOf(g) < 0) groups.push(g); }); });
    return '<section><h4>Jabber · this desk is ext 8443</h4>' + groups.sort().map(function (g) {
      var list = team.filter(function (p) { return p.groups.indexOf(g) >= 0; }).sort(function (a, b) { return STATE_RANK[a.state] - STATE_RANK[b.state] || a.name.localeCompare(b.name); });
      return '<div style="margin-top:6px;font-weight:bold">' + esc(g) + '</div>' + list.map(personRow).join('');
    }).join('') + '</section>';
  }

  function showQr() {
    var box = panel.querySelector('#qfd-pairbox'), qr = panel.querySelector('#qfd-qr');
    box.hidden = false; qr.innerHTML = '';
    panel.querySelector('#qfd-link').textContent = pairLink();
    if (window.QRCode) new QRCode(qr, { text: pairLink(), width: 200, height: 200, correctLevel: QRCode.CorrectLevel.M });
    else qr.textContent = '(QR library did not load — type the link above into Safari)';
  }
  function toast(msg) {
    if (!toastBox) return;
    var t = document.createElement('div'); t.className = 'qfd-toast'; t.textContent = msg;
    toastBox.appendChild(t);
    setTimeout(function () { t.style.opacity = '0'; }, 3500);
    setTimeout(function () { t.remove(); }, 4000);
  }
})();
