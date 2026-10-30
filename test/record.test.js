// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const Q = require('..');
const key = () => Q.generateKey();
const reg = (k, o) => Q.register({ key: k, vin: 'WDB1234567890', vehicleClass: 'car', make: 'Acme', model: 'X1', year: 2026, jurisdiction: 'gb', plate: 'AB26 XYZ', owner: Q.keyId(o), registrarLabel: 'DVLA' });

test('a registered vehicle is a well formed signed record of the registrar', () => {
  const r = key(); const o = key(); const t = reg(r, o);
  assert.strictEqual(t.format, 'qvehicle/1');
  assert.strictEqual(t.type, 'register');
  assert.strictEqual(t.signer.id, Q.keyId(r));
  assert.strictEqual(t.statement.ownerKeyId, Q.keyId(o));
  assert.strictEqual(t.statement.vehicleClass, 'car');
  assert.match(t.statement.vehicleId, /^[0-9a-f]{32}$/);
});

test('inspect transfer deregister chain to the same vehicle', () => {
  const r = key(); const o = key(); const insp = key(); const buyer = key();
  const t = reg(r, o);
  const i = Q.inspect({ key: insp, vehicle: t, outcome: 'pass', odometerKm: 12000 });
  const moved = Q.transfer({ key: o, vehicle: t, to: Q.keyId(buyer) });
  const gone = Q.deregister({ key: r, vehicle: moved, reason: 'exported' });
  assert.strictEqual(i.statement.vehicleId, t.statement.vehicleId);
  assert.strictEqual(i.statement.outcome, 'pass');
  assert.strictEqual(i.statement.odometerKm, 12000);
  assert.strictEqual(moved.statement.toKeyId, Q.keyId(buyer));
  assert.strictEqual(gone.statement.reason, 'exported');
});

test('invalid inputs are refused before anything is signed', () => {
  const k = key(); const o = key();
  const base = { key: k, vin: 'V1', vehicleClass: 'car', make: 'A', model: 'B', year: 2026, jurisdiction: 'gb', owner: Q.keyId(o) };
  assert.throws(() => Q.register(Object.assign({}, base, { vehicleClass: 'spaceship' })), /vehicleClass must be one of/);
  assert.throws(() => Q.register(Object.assign({}, base, { year: 1800 })), /year must be a whole number of at least/);
  assert.throws(() => Q.register(Object.assign({}, base, { jurisdiction: 'GB' })), /jurisdiction must be/);
  assert.throws(() => Q.register(Object.assign({}, base, { zzz: 1 })), /is not an option of register/);
  const t = reg(k, o);
  assert.throws(() => Q.inspect({ key: key(), vehicle: t, outcome: 'maybe', odometerKm: 1 }), /outcome must be one of/);
});

test('a well formed record verifies and a type mismatch or tamper is invalid', async () => {
  const r = key(); const o = key(); const t = reg(r, o);
  const OPTS = { network: 'testnet', requireAnchor: false, strict: false };
  const ok = await Q.verify(t, Object.assign({ type: 'register' }, OPTS));
  assert.strictEqual(ok.status, 'valid');
  assert.strictEqual(ok.vehicleId, t.statement.vehicleId);
  assert.strictEqual((await Q.verify(t, Object.assign({ type: 'transfer' }, OPTS))).status, 'invalid');
  const f = JSON.parse(JSON.stringify(t)); f.statement.year = 2000;
  assert.strictEqual((await Q.verify(f, Object.assign({ type: 'register' }, OPTS))).status, 'invalid');
});

test('the prior link binds and the kind and constants are pinned', async () => {
  const r = key(); const o = key(); const insp = key();
  const t = reg(r, o);
  const i = Q.inspect({ key: insp, vehicle: t, outcome: 'pass', odometerKm: 12000 });
  const good = await Q.verify(i, { type: 'inspect', network: 'testnet', requireAnchor: false, strict: false, prior: t });
  assert.ok(good.checks.some((c) => c.name === 'prior' && c.ok));
  assert.strictEqual(Q.KIND, 1307);
  assert.strictEqual(Q.FORMAT, 'qvehicle/1');
  assert.deepStrictEqual([...Q.TYPES], ['register', 'inspect', 'transfer', 'deregister']);
});
