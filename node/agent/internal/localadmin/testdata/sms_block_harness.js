// Drives the real app.js against a stub DOM and a scripted device, to check
// what the SMS page does when the device refuses a send. Run by
// sms_block_js_test.go with: node sms_block_harness.js <path to app.js>
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
    append(...nodes) { base.children.push(...nodes); }, replaceChildren(...nodes) { base.children = nodes; },
    closest() { return null; }, querySelector() { return fakeElement(''); }, querySelectorAll() { return []; },
    focus() { base.focused = (base.focused || 0) + 1; }, reset() {}, click() {}, remove() {}, scrollIntoView() {},
    // Handlers start their work without returning it (busy()), so give it time.
    async fire(type, event) { for (const fn of listeners[type] || []) fn(event || { preventDefault() {}, submitter: null }); await new Promise(resolve => setTimeout(resolve, 60)); },
  };
  return base;
}
const $ = id => { if (!elements.has(id)) elements.set(id, fakeElement(id)); return elements.get(id); };

// The scripted device.
const device = { sends: [], sendAnswers: [], trust: { supported: true, installed: false, send_sms_allowed: true, deny: [] }, trustReads: 0, trustFails: false };
function json(status, body) { return { ok: status >= 200 && status < 300, status, headers: { get() { return ''; } }, json: async () => body, blob: async () => ({}) }; }
async function fetchStub(path, options = {}) {
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

const settle = ms => new Promise(resolve => setTimeout(resolve, ms));
const failures = [];
function check(condition, message) { if (!condition) failures.push(message); }
const block = () => $('sms-block');
const refusal = (code, state) => ({ status: 403, body: { error: 'device wording', code, state } });

(async () => {
  await settle(100); // session + first refresh
  // Opening the SMS page with nothing restricted: no explanation shown.
  block().hidden = true;
  await $('sms-refresh').fire('click');
  check(block().hidden === true, 'no block is shown while the device allows sending');

  const cases = [
    ['trust_stale_restart', 'TRUSTED', '等待 NAS 确认', 'NAS 连接后会自动确认'],
    ['trust_stale', 'TRUSTED', '已过期', '自动下发新的策略'],
    ['trust_denied', 'OBSERVATION', '观察期', '期满后自动允许外发'],
    ['trust_denied', 'RESTRICTED', '已被限制外发', '执行「恢复」'],
    ['trust_denied', 'QUARANTINE', '已被隔离', '执行「恢复」'],
    ['trust_damaged', '', '校验失败', '重新下发策略'],
    ['trust_denied', 'SOMETHING_NEW', 'NAS 限制了这台设备的外发', '本页不能解除'],
    ['trust_from_the_future', '', 'NAS 限制了这台设备的外发', '本页不能解除'],
  ];
  const titles = new Set();
  for (const [code, state, title, recover] of cases) {
    const draft = '草稿 ' + code + ' ' + state;
    $('sms-number').value = '10000'; $('sms-text').value = draft;
    const before = device.sends.length;
    device.sendAnswers.push(refusal(code, state));
    await $('sms-form').fire('submit');
    await settle(250); // long enough for any hidden retry to show up
    const name = code + '/' + state;
    check(device.sends.length === before + 1, name + ': exactly one request was sent, got ' + (device.sends.length - before));
    check(block().hidden === false, name + ': the explanation is shown');
    check($('sms-block-title').textContent.includes(title), name + ': title says "' + title + '", got "' + $('sms-block-title').textContent + '"');
    check($('sms-block-recover').textContent.includes(recover), name + ': recovery says "' + recover + '", got "' + $('sms-block-recover').textContent + '"');
    check($('sms-block-draft').textContent.includes('草稿已保留') && $('sms-block-draft').textContent.includes('不会自动重试'), name + ': says the draft is kept and nothing is retried');
    check($('sms-text').value === draft && $('sms-number').value === '10000', name + ': the draft is untouched');
    check($('sms-submit').disabled === false, name + ': the send button is not disabled by the page');
    check(!$('notice').textContent.includes('device wording') || $('notice').hidden, name + ': the refusal is explained in the SMS card, not only as a passing notice');
    titles.add($('sms-block-title').textContent);
  }
  check(titles.size === 7, 'the six known situations and the fallback read differently, got ' + titles.size + ' distinct titles');

  // Recovery, the main case: restart -> NAS confirms -> the person sends again.
  const draft = '重启后的草稿';
  $('sms-number').value = '10000'; $('sms-text').value = draft;
  device.sendAnswers.push(refusal('trust_stale_restart', 'TRUSTED'));
  await $('sms-form').fire('submit');
  const sent = device.sends.length, firstID = device.sends[sent - 1].request_id;

  // Re-check while still waiting: the device's own classification is shown.
  device.trust = { supported: true, installed: true, enforcing: true, stale: true, freshness: 'stale_restart', state: 'TRUSTED', deny: [], send_sms_allowed: false, send_sms_block: 'trust_stale_restart' };
  await $('sms-block-recheck').fire('click');
  check(block().hidden === false && $('sms-block-title').textContent.includes('等待 NAS 确认'), 're-check while waiting keeps the explanation');
  check(device.sends.length === sent, 're-check never sends');

  // The policy cannot be read: "could not ask" is not "allowed".
  device.trustFails = true;
  await $('sms-block-recheck').fire('click');
  check(block().hidden === false, 'an unreadable policy does not clear the explanation');
  check($('notice').textContent.includes('无法确认'), 'an unreadable policy is reported as unknown');
  device.trustFails = false;
  // An answer that does not say whether sending is allowed is not "allowed" either.
  device.trust = { supported: true, installed: true };
  await $('sms-block-recheck').fire('click');
  check(block().hidden === false, 'an answer without send_sms_allowed does not clear the explanation');
  check(device.sends.length === sent, 'an unclear answer sends nothing');

  // The NAS confirmed. Re-check clears the explanation, keeps the draft, sends nothing.
  device.trust = { supported: true, installed: true, enforcing: true, stale: false, freshness: 'fresh', state: 'TRUSTED', deny: [], send_sms_allowed: true };
  await $('sms-block-recheck').fire('click');
  await settle(250);
  check(block().hidden === true, 'after the NAS confirmed, the explanation is cleared');
  check($('sms-text').value === draft, 'after recovery the draft is still there');
  check(device.sends.length === sent, 'recovery does not send the draft by itself');
  check($('notice').textContent.includes('再点一次'), 'the person is told to press send themselves');

  // The person presses send: it goes out once, with the same request id, and the draft is cleared.
  device.sendAnswers.push({ status: 201, body: { message_id: 'm1' } });
  await $('sms-form').fire('submit');
  check(device.sends.length === sent + 1 && device.sends[sent].request_id === firstID, 'the manual send after recovery reuses the request id of the refused attempt');
  check($('sms-text').value === '', 'a sent message clears the draft');
  check(block().hidden === true, 'no explanation after a successful send');

  // Opening the page while restricted shows the reason before anything is typed, from the device's answer.
  device.trust = { supported: true, installed: true, enforcing: true, stale: false, state: 'OBSERVATION', deny: ['dial', 'dtmf', 'send_sms'], send_sms_allowed: false, send_sms_block: 'trust_denied' };
  await $('sms-refresh').fire('click');
  check(block().hidden === false && $('sms-block-title').textContent.includes('观察期'), 'opening the page under observation shows why');
  check($('sms-block-draft').textContent.includes('当前的状态'), 'with no draft the page does not talk about a kept draft');
  check($('sms-submit').disabled === false, 'the page does not decide permission by disabling the button');
  // A device that says "not allowed" without saying why: nothing is invented.
  hideAll();
  device.trust = { supported: true, installed: true, send_sms_allowed: false };
  await $('sms-refresh').fire('click');
  check(block().hidden === true, 'no reason from the device means no explanation is made up');

  if (failures.length) { console.error(failures.join('\n')); process.exit(1); }
  console.log('sms block harness: ' + (cases.length) + ' refusal cases and the recovery sequence passed');
  process.exit(0);
})().catch(err => { console.error(err); process.exit(1); });

function hideAll() { block().hidden = true; }
