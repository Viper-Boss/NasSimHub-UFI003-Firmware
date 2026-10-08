// Drives the real app.js against a stub DOM and a scripted device, to check
// account mutations, password clearing and SSH settings. Run with:
// node system_harness.js <path to app.js>
// It is a simulation: no browser, no device.
'use strict';
const fs = require('fs'), vm = require('vm');

const elements = new Map();
function fakeElement(id) {
  const listeners = {}, attributes = {};
  const base = {
    id, value: '', textContent: '', hidden: false, disabled: false, children: [], dataset: {}, style: {}, className: '',
    classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } },
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    setAttribute(k, v) { attributes[k] = String(v); }, getAttribute(k) { return attributes[k] ?? null; }, removeAttribute(k) { delete attributes[k]; },
    appendChild(node) { base.children.push(node); }, append(...nodes) { base.children.push(...nodes); }, replaceChildren(...nodes) { base.children = nodes; },
    closest() { return null; }, querySelector() { return fakeElement(''); }, querySelectorAll() { return []; },
    focus() { base.focused = (base.focused || 0) + 1; }, reset() {}, click() {}, remove() {}, scrollIntoView() {},
    // Handlers start their work without returning it (busy()), so give it time.
    async fire(type, event) { for (const fn of listeners[type] || []) fn(event || { preventDefault() {}, submitter: null }); await new Promise(resolve => setTimeout(resolve, 60)); },
  };
  return base;
}
const $ = id => { if (!elements.has(id)) elements.set(id, fakeElement(id)); return elements.get(id); };

// The scripted device.
const systemCalls = [];
const systemState = { accounts: [], ssh: {port:2222,enabled:false,password_login:false,root_login:false},running:false };
const device = { sends: [], sendAnswers: [], trust: { supported: true, installed: false, send_sms_allowed: true, deny: [] }, trustReads: 0, trustFails: false };
function json(status, body) { return { ok: status >= 200 && status < 300, status, headers: { get() { return ''; } }, json: async () => body, blob: async () => ({}) }; }
async function fetchStub(path, options = {}) {
  if (path === '/admin/api/v1/system/change') { systemCalls.push(JSON.parse(options.body)); return json(200,systemState); }
  if (path === '/admin/api/v1/system') return json(200,systemState);
  if (path === '/admin/session') return json(200, { authenticated: true, configured: true, csrf: 'fake-csrf', device_id: 'NSH-TEST-000000', model: 'test', version: '0.0.0-test' });
  if (path === '/admin/api/v1/trust') { device.trustReads++; return device.trustFails ? json(500, { error: 'simulated', code: 'internal' }) : json(200, device.trust); }
  if (path === '/admin/api/v1/sms/send') { device.sends.push(JSON.parse(options.body)); const next = device.sendAnswers.shift(); return json(next.status, next.body); }
  if (path === '/admin/api/v1/sms') return json(200, { messages: [] });
  return json(200, {});
}

const sandbox = {
  document: { getElementById: $, querySelectorAll() { return []; }, querySelector() { return fakeElement(''); }, createElement: () => fakeElement(''),
    createElementNS: () => fakeElement(''), addEventListener() {}, hidden: false, title: '', activeElement: null, body: fakeElement('body') },
  location: { hash: '', pathname: '/', search: '', origin: 'https://device.test', protocol: 'https:' },
  history: { replaceState() {} }, navigator: {}, fetch: fetchStub, confirm: () => true, alert() {},
  crypto: { randomUUID: () => 'fake-uuid-' + (++sandbox.uuids), getRandomValues: a => a }, uuids: 0,
  AbortController, URLSearchParams, URL, TextEncoder, setTimeout, clearTimeout, setInterval, clearInterval, console, Blob: class {},
};
sandbox.window = sandbox; sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), sandbox, { filename: 'app.js' });


(async () => {
 await new Promise(r=>setTimeout(r,100));
 $('system-action').value='create'; $('system-user').value='alice';
 $('system-new-password').value='random-password-123'; $('system-confirm').value='different'; $('system-account-current').value='admin-password-123';
 await $('system-account-form').fire('submit');
 if(systemCalls.length)throw Error('mismatch submitted');
 $('system-confirm').value='random-password-123';
 await $('system-account-form').fire('submit');
 if(systemCalls.length!==1||systemCalls[0].action!=='create'||systemCalls[0].current_password!=='admin-password-123')throw Error('create missing or duplicated');
 if($('system-new-password').value||$('system-confirm').value||$('system-account-current').value)throw Error('password remained in page');
 $('system-enabled').checked=true;$('system-port').value='2222';$('system-root-login').checked=true;$('system-ssh-current').value='admin-password-123';
 await $('system-ssh-form').fire('submit');
 if(systemCalls.length!==2||!systemCalls[1].ssh.root_login||!systemCalls[1].ssh.enabled)throw Error('SSH settings incorrect');
 await new Promise(r=>setTimeout(r,200));
 if(systemCalls.length!==2)throw Error('automatic retry');
 console.log('system administration UI simulation passed');process.exit(0);
})().catch(e=>{console.error(e);process.exit(1)});
