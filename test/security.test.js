// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');
const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
function veh() { const key = Q.generateKey(); const owner = Q.generateKey(); return { key, env: Q.register({ key, vin: 'WDB1234567890', vehicleClass: 'car', make: 'Acme', model: 'X1', year: 2026, jurisdiction: 'gb', owner: Q.keyId(owner) }) }; }

test('replay as another type or vehicle id is refused', async () => {
  const { env } = veh();
  const t = JSON.parse(JSON.stringify(env)); t.type = 'transfer';
  assert.strictEqual((await Q.verify(t, Object.assign({ type: 'transfer' }, OPTS))).status, 'invalid');
  const i = JSON.parse(JSON.stringify(env)); i.statement.vehicleId = 'f'.repeat(32);
  assert.strictEqual((await Q.verify(i, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
});

test('every signed field is bound', async () => {
  const { env } = veh();
  for (const m of [(s) => { s.vin = 'X'; }, (s) => { s.vehicleClass = 'truck'; }, (s) => { s.make = 'Z'; }, (s) => { s.year += 1; }, (s) => { s.plate = 'ZZ'; }, (s) => { s.registeredAt = '2000-01-01T00:00:00.000Z'; }]) {
    const f = JSON.parse(JSON.stringify(env)); m(f.statement);
    assert.strictEqual((await Q.verify(f, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
  }
});

test('wrong signer, bad base64, extra field, prototype pollution, hidden key, wrong anchor kind', async () => {
  const a = veh(); const b = veh();
  const ws = JSON.parse(JSON.stringify(a.env)); ws.signer = b.env.signer;
  assert.strictEqual((await Q.verify(ws, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
  const bb = JSON.parse(JSON.stringify(a.env)); bb.signature = bb.signature.slice(0, -4) + 'AAAA';
  assert.strictEqual((await Q.verify(bb, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
  const ex = JSON.parse(JSON.stringify(a.env)); ex.statement.extra = 1;
  assert.strictEqual((await Q.verify(ex, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
  const po = JSON.parse(JSON.stringify(a.env)); po.statement = JSON.parse('{"__proto__":{"x":1},"vehicleId":"' + a.env.statement.vehicleId + '"}');
  assert.strictEqual((await Q.verify(po, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
  assert.strictEqual({}.x, undefined);
  assert.strictEqual(JSON.stringify({ k: Q.generateKey() }), '{"k":"SecretKey [hidden]"}');
  const an = JSON.parse(JSON.stringify(a.env)); an.anchor = { kind: '1301', chain: { id: 'x', genesis: 'y' }, anchor: { time: 1, height: 1, tx: 't' }, proof: { index: 0 } };
  assert.strictEqual((await Q.verify(an, { type: 'register', network: 'testnet', requireAnchor: true, strict: false })).status, 'invalid');
});
