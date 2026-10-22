// ==UserScript==
// @name         Qless Front Desk Assistant
// @namespace    qless-front-desk
// @version      1.0.0
// @description  iPhone voice remote, CWID auto-fill, keyboard shortcuts and a daily counter for Qless
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
      self.o = o; self.role = o.role; self.peer = o.role === 'pc' ? 'phone' : 'pc';
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
  (function waitForQless() { if (ready()) init(); else setTimeout(waitForQless, 300); })();

  var acvm, relay, pairing, currentLookup = null, last = null, remoteBusy = false, panel, pill, toastBox;

  function init() {
    acvm = vm.addConsumerVM;
    log('ready');
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
      onStatus: function () { renderPill(); }
    });
    setTimeout(function () { publishState(true); }, 1500);
  }
  function onPhoneMessage(m) {
    if (m.t === 'hello') publishState(true);
    else if (m.t === 'fill') queueFill(m);
    else if (m.t === 'cancel') { if (vm.showAddConsumer()) acvm.cancelAddConsumer(); currentLookup = null; publishState(); }
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
      await sleep(300);
    } else if (qid && !(acvm.queueIds().length === 1 && Number(acvm.queueIds()[0]) === qid)) {
      acvm.queueIds([qid]);
      await sleep(250);
    }
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
      await sleep(600); // let anything else that reacts to the lookup (e.g. the old V5 script) finish first
    }
    if (f.name && !String(acvm.consumerName() || '').trim()) acvm.consumerName(f.name);
    var cwid = f.cwid || (lk && lk.phone === f.phone ? lk.cwid : null);
    if (cwid || f.note) acvm.notes(formatNote(cwid, f.note));
    else if (lk && lk.phone === f.phone && !acvm.notes()) acvm.notes(formatNote('', ''));
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
    acvm.addCustomerToQueue();
    var res = await waitAddResult();
    if (res.ok) {
      var msg = 'Added ' + info.name + ' → ' + info.queue.replace(/^.*? - /, '') + (info.service ? ' · ' + info.service : '');
      setLast({ status: 'added', msg: msg, reqId: reqId });
      toast('✅ ' + msg);
    } else {
      setLast({ status: 'error', msg: res.msg, reqId: reqId });
      toast('⚠️ ' + res.msg);
    }
  }
  function setLast(l) { last = l; publishState(); }

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
      '#qfd-toasts{position:fixed;top:90px;right:14px;z-index:100000;display:flex;flex-direction:column;gap:6px;align-items:flex-end}',
      '.qfd-toast{background:#333;color:#fff;padding:8px 12px;border-radius:6px;font:13px Arial,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.25);transition:opacity .4s}'
    ].join('\n');
    document.head.appendChild(css);
    pill = document.createElement('div'); pill.id = 'qfd-pill'; pill.title = 'Front Desk Assistant';
    pill.onclick = function () { panel.hidden = !panel.hidden; if (!panel.hidden) renderPanel(); };
    toastBox = document.createElement('div'); toastBox.id = 'qfd-toasts';
    panel = document.createElement('div'); panel.id = 'qfd-panel'; panel.hidden = true;
    document.body.appendChild(pill); document.body.appendChild(panel); document.body.appendChild(toastBox);
    renderPill();
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
      '<section><h4>Today · ' + s.total + ' students</h4><table>' + (rows || '<tr><td style="color:#999">Nobody yet</td><td></td></tr>') + '</table>' +
      '<div style="margin-top:6px"><button class="grey" id="qfd-reset">Reset today</button></div></section>' +
      '<section><h4>Shortcuts</h4>' + qs + '<div><kbd>Ctrl+Enter</kbd> Add (submit)</div><div><kbd>Esc</kbd> Close the form</div>' +
      '<div style="color:#888;font-size:11px;margin-top:4px">Phone field is focused automatically; after the lookup the cursor jumps to Notes.</div></section>' +
      '<section><h4>Phone app address</h4><input id="qfd-url" value="' + esc(phoneUrl()) + '"></section>';
    panel.querySelector('#qfd-close').onclick = function () { panel.hidden = true; };
    panel.querySelector('#qfd-pair').onclick = showQr;
    panel.querySelector('#qfd-repair').onclick = function () {
      pairing = QRelay.newPairing(); store.set('pairing', pairing); startRelay(); renderPanel(); showQr();
    };
    panel.querySelector('#qfd-reset').onclick = function () { store.set('stats', null); renderPill(); };
    panel.querySelector('#qfd-url').onchange = function (e) { store.set('phoneUrl', e.target.value.trim()); };
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
