// ==UserScript==
// @name         Qless Front Desk Assistant
// @namespace    qless-front-desk
// @version      2.1.0
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
  
    // lowercase, no accents/punctuation, plural "s" dropped so "transcripts" matches "transcript"
    function norm(s) {
      return ' ' + String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '')
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
      var m = ROOM_RE.exec(String(text || '').split(/\s+/).slice(-30).join(' '));
      if (!m) return null;
      var k = m[1].toLowerCase().replace(/^w(?=cc|sc)/, '');
      var b = /cc|commons/.test(k) ? 'CC' : /sc|student/.test(k) ? 'SC' : 'L';
      var room = m[2] + m[3] + (m[4] || '').toUpperCase(), floor = Number(m[2]);
      var name = { CC: 'Campus Commons', SC: 'Student Center', L: 'Library' }[b];
      return { id: 'room:' + b + room, kind: 'place', title: name + ' ' + room, say: route(b, floor, room), facts: [], queue: null };
    }
    function today() { var d = new Date(); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); }
    var WHERE_RE = /\b(where|wheres|how do i get|how do i find|how to get|location|located|which building|what building|what room|donde|dónde)\b/i;
  
    function load(data) {
      kb = data; index = [];
      (kb.places || []).forEach(function (pl) {
        kb.cards.push({ id: 'place-' + pl.id, kind: 'place', title: pl.name + (pl.room && pl.b !== 'off' ? ' — ' + (pl.b === 'L' ? 'Library ' : pl.b + ' ') + pl.room : ''),
          say: pl.say || route(pl.b, pl.floor, pl.room), facts: pl.facts || [], triggers: pl.triggers, until: pl.until });
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
      var out = { id: c.id, kind: c.kind || 'tip', title: c.title, say: c.say, facts: (c.facts || []).slice(), queue: c.queue || null };
      if (c.dates) upcoming(400, c.dates).slice(0, 3).forEach(function (d) { out.facts.push(fmtDate(d.date) + ': ' + d.label); });
      return out;
    }
  
    return {
      decrypt: decrypt, load: load, match: match, byId: byId, upcoming: upcoming, fmtDate: fmtDate,
      keyterms: function () { return (kb && kb.keyterms) || []; },
      loaded: function () { return !!kb; },
      version: function () { return kb && kb.version; }
    };
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
      .then(function (data) { QKB.load(data); log('knowledge base', QKB.version()); renderLive(); })
      .catch(function (e) { log('knowledge base not loaded', e); });
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
      var ta = document.getElementById('addConsumerNotes');
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
  function focusEl(id) { var el = document.getElementById(id); if (el && !el.disabled) el.focus(); }
  function installShortcuts() {
    document.addEventListener('keydown', function (e) {
      if (e.altKey && !e.ctrlKey && /^[1-9]$/.test(e.key)) {
        var q = vm.selectedQueues()[Number(e.key) - 1];
        if (q) { e.preventDefault(); openQueue(q.id); setTimeout(function () { focusEl('phoneInput'); }, 200); }
      } else if ((e.ctrlKey || e.altKey) && e.key === 'Enter' && vm.showAddConsumer()) {
        e.preventDefault(); acvm.addCustomerToQueue();
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
  }
  // Who's available, from the Jabber helper running on this PC (desk/desk-agent.js).
  function startDesk() {
    var d = store.get('desk', null);
    if (!d || deskRelay) return;
    deskRelay = new QRelay.Relay({
      topic: d.topic, key: d.key, role: 'pc', peer: 'desk',
      onMessage: function (m) { if (m.t === 'presence') { team = m.people || []; teamAt = Date.now(); renderLive(); if (panel && !panel.hidden) renderPanel(); } }
    });
  }
  function onPhoneMessage(m) {
    if (m.t === 'hello') { publishState(true); sendConfig(); }
    else if (m.t === 'fill') queueFill(m);
    else if (m.t === 'live') { live = m; liveAt = Date.now(); renderLive(); }
    else if (m.t === 'cancel') { if (vm.showAddConsumer()) acvm.cancelAddConsumer(); currentLookup = null; live = null; renderLive(); publishState(); }
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
    var input = document.getElementById('phoneInput');
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
      await waitFor(function () { return vm.showAddConsumer() && document.getElementById('phoneInput'); }, 500);
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
      await setPhone(f.phone);
      var prev = acvm.consumerInfoWS && ko.unwrap(acvm.consumerInfoWS.notes);
      var nm = String(acvm.consumerName() || '').trim();
      currentLookup = lk = { phone: f.phone, name: nm, cwid: cwidFrom(prev), known: !!(nm || prev) };
      await sleep(120);
    }
    if (f.name && !String(acvm.consumerName() || '').trim()) acvm.consumerName(f.name);
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
      lookup: currentLookup, last: last,
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
      '<section><h4>Setup</h4>' +
      '<div style="margin-bottom:6px">Deepgram key (speech AI)<input id="qfd-dg" type="password" value="' + esc(store.get('dgKey', '')) + '" placeholder="paste key"></div>' +
      '<div style="margin-bottom:6px">Your name (so it never mistakes you for the student)<input id="qfd-me" value="' + esc(store.get('me', '')) + '"></div>' +
      '<div style="font-size:12px;color:#666">Knowledge base: ' + (QKB.loaded() ? '✅ ' + esc(QKB.version()) : store.get('kbKey', '') ? '⏳ loading / failed' : '❌ no key — open your setup link') + '</div></section>' +
      '<section><h4>Phone app address</h4><input id="qfd-url" value="' + esc(phoneUrl()) + '"></section>';
    panel.querySelector('#qfd-close').onclick = function () { panel.hidden = true; };
    panel.querySelector('#qfd-pair').onclick = showQr;
    panel.querySelector('#qfd-repair').onclick = function () {
      pairing = QRelay.newPairing(); store.set('pairing', pairing); startRelay(); renderPanel(); showQr();
    };
    panel.querySelector('#qfd-reset').onclick = function () { store.set('stats', null); renderPill(); };
    panel.querySelector('#qfd-url').onchange = function (e) { store.set('phoneUrl', e.target.value.trim()); };
    panel.querySelector('#qfd-dg').onchange = function (e) { store.set('dgKey', e.target.value.trim()); sendConfig(); toast('Sent to iPhone'); };
    panel.querySelector('#qfd-me').onchange = function (e) { store.set('me', e.target.value.trim()); sendConfig(); };
  }
  // ---------- live assistant overlay (captions, detected fields, countdown, tips) ----------
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
    liveBox.hidden = !st.peerOnline && !fresh && !team.length;
    if (liveBox.hidden) return;
    var speaking = live && Date.now() - liveAt < 4000 && live.text;
    var h = '<div class="hd" id="qfd-live-hd"><span class="dot' + (speaking ? ' on' : '') + '"></span>' +
      (speaking ? 'Listening' : 'iPhone ready') +
      (live && live.lang && live.lang !== 'en' ? ' <span class="lang">🌐 ' + esc(LANG_NAMES[live.lang] || live.lang) + '</span>' : '') +
      '<span style="margin-left:auto;font-weight:normal;color:#888">' + bossLink() + ' ' + (liveBox.classList.contains('min') ? '▸' : '▾') + '</span></div><div class="body">';
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
      h += '<div class="tip' + (c.kind === 'place' ? ' place' : '') + '"><b>' + ({ staff: '👤 ', place: '📍 ' }[c.kind] || '💡 ') + esc(c.title) + '</b>' + (c.say ? '<div class="say">' + esc(c.say) + '</div>' : '') +
        (c.facts.length ? '<ul>' + c.facts.slice(0, 4).map(function (x) { return '<li>' + esc(x) + '</li>'; }).join('') + '</ul>' : '') + '</div>';
    });
    h += teamHtml(tips);
    var up = QKB.loaded() ? QKB.upcoming(14) : [];
    if (up.length && !tips.length) h += '<div class="up"><b>Coming up</b>' + up.slice(0, 4).map(function (d) { return '<div>' + esc(QKB.fmtDate(d.date)) + ' — ' + esc(d.label) + '</div>'; }).join('') + '</div>';
    h += '</div>';
    liveBox.innerHTML = h;
    liveBox.querySelector('#qfd-live-hd').onclick = function () { liveBox.classList.toggle('min'); store.set('liveMin', liveBox.classList.contains('min')); renderLive(); };
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
