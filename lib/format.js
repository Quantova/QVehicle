// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const nodeCrypto = require('crypto');

const FORMAT = 'qvehicle/1';
const ALGORITHM = 'ML-DSA-65';
const KIND = 1307;
const TYPES = Object.freeze(['register', 'inspect', 'transfer', 'deregister']);
const CLASSES = Object.freeze(['car', 'truck', 'bus', 'motorcycle', 'trailer', 'vessel', 'aircraft', 'rail']);
const OUTCOMES = Object.freeze(['pass', 'advisory', 'fail']);
const KEY_DOMAIN = Buffer.from('quantova/qvehicle/key/1', 'ascii');
const REF_DOMAIN = Buffer.from('quantova/qvehicle/ref/1', 'ascii');
const ANCHOR_DOMAIN = Buffer.from('quantova/qvehicle/anchor/1', 'ascii');
const VEHICLE_DOMAIN = Buffer.from('quantova/qvehicle/vehicle/1', 'ascii');
const MAGIC = Buffer.from('QVEH', 'ascii');
const VERSION = 1;
const PUBLIC_KEY_BYTES = 1952;
const SIGNATURE_BYTES = 3309;
const LABEL_MAX = 200;
const NOTE_MAX = 1000;
const REF_MAX = 120;
const MAX_ODOMETER_KM = 100000000;
const MIN_YEAR = 1900;
const MAX_YEAR = 2200;
const HEX32 = /^[0-9a-f]{64}$/;
const HEX16 = /^[0-9a-f]{32}$/;
const CODE = /^[a-z][a-z0-9_]{0,39}$/;
const IDENT = /^[A-Za-z0-9][A-Za-z0-9 ./-]{0,119}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const UNSAFE_TEXT = /[\p{Cc}\p{Cf}\p{Co}\p{Cn}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}\u00a0\u1680\u2000-\u200a\u202f\u205f\u3000\u2800\u115f\u1160\u3164\uffa0]/u;

const FIELDS = Object.freeze({
  register: ['vehicleId', 'vin', 'vehicleClass', 'make', 'model', 'year', 'jurisdiction', 'plate', 'ownerKeyId', 'registrarKeyId', 'registrarLabel', 'registeredAt', 'note'],
  inspect: ['vehicleId', 'vehicleRef', 'outcome', 'odometerKm', 'inspectorKeyId', 'inspectorLabel', 'inspectedAt', 'note'],
  transfer: ['vehicleId', 'vehicleRef', 'fromKeyId', 'toKeyId', 'toLabel', 'transferredAt', 'note'],
  deregister: ['vehicleId', 'vehicleRef', 'registrarKeyId', 'reason', 'deregisteredAt', 'note'],
});

function fail(message) {
  const e = new Error('the envelope is not valid, ' + message);
  e.code = 'QVEHICLE_INVALID_ENVELOPE';
  throw e;
}

function reject(message) {
  const e = new Error(message);
  e.code = 'QVEHICLE_INVALID_INPUT';
  throw e;
}

function sha3(...parts) {
  const h = nodeCrypto.createHash('sha3-256');
  for (const p of parts) h.update(p);
  return h.digest();
}

function keyIdOf(publicKey) {
  if (!((ArrayBuffer.isView(publicKey) && publicKey instanceof Uint8Array)) || publicKey.length !== PUBLIC_KEY_BYTES) reject('a public key is ' + PUBLIC_KEY_BYTES + ' bytes');
  return sha3(KEY_DOMAIN, Buffer.from([0]), publicKey).toString('hex');
}

function vehicleRefOf(secret, reference) {
  if (!((ArrayBuffer.isView(secret) && secret instanceof Uint8Array)) || secret.length !== 32) reject('the vehicle secret is a 32 byte Uint8Array held by the registry');
  if (new Set(secret).size < 13) reject('a vehicle secret made of too few different byte values is refused, draw it from a secure random source');
  if (typeof reference !== 'string' || reference.length === 0 || reference.length > REF_MAX) reject('the vehicle reference is 1 to ' + REF_MAX + ' characters');
  if (!IDENT.test(reference)) reject('the vehicle reference holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit');
  return sha3(VEHICLE_DOMAIN, Buffer.from([0]), Buffer.from(secret), Buffer.from(reference, 'utf8')).toString('hex');
}

function textProblem(value, max, what, required) {
  if (typeof value !== 'string') return what + ' must be text';
  if (required && value.length === 0) return what + ' cannot be empty';
  if (value.length > max) return what + ' is longer than ' + max + ' characters';
  if (!value.isWellFormed()) return what + ' holds a broken Unicode surrogate';
  if (value.normalize('NFC') !== value) return what + ' must be in Unicode normal form C';
  if (UNSAFE_TEXT.test(value)) return what + ' holds control, invisible or direction characters';
  return null;
}

function timeProblem(value, what) {
  if (typeof value !== 'string' || !ISO_UTC.test(value)) return what + ' must be an ISO 8601 UTC time with milliseconds and a Z suffix';
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value) return what + ' is not a real calendar time';
  return null;
}

function pattern(value, re, what, rule) {
  if (typeof value !== 'string' || !re.test(value)) return what + ' must be ' + rule;
  return null;
}

function refProblem(value, what) {
  if (typeof value !== 'string' || !HEX32.test(value)) return what + ' must be 64 lowercase hex characters';
  return null;
}

function codeProblem(value, what) {
  if (typeof value !== 'string' || !CODE.test(value)) return what + ' must be lowercase letters, digits or underscores, 1 to 40 characters, starting with a letter';
  return null;
}

function enumProblem(value, allowed, what) {
  if (typeof value !== 'string' || !allowed.includes(value)) return what + ' must be one of ' + allowed.join(', ');
  return null;
}

function intProblem(value, min, max, what) {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min) return what + ' must be a whole number of at least ' + min;
  if (value > max) return what + ' is larger than ' + max;
  return null;
}

function identProblem(value, what) {
  if (typeof value !== 'string' || value.length === 0 || value.length > REF_MAX) return what + ' is 1 to ' + REF_MAX + ' characters';
  if (!IDENT.test(value)) return what + ' holds letters, digits, spaces, dots, slashes or hyphens and starts with a letter or digit';
  return null;
}

function statementProblem(type, st) {
  if (!TYPES.includes(type)) return 'type must be one of ' + TYPES.join(', ');
  if (st === null || typeof st !== 'object' || Array.isArray(st)) return 'the statement must be an object';
  const fields = FIELDS[type];
  if (Object.keys(st).sort().join(',') !== fields.slice().sort().join(',')) return 'a ' + type + ' statement holds exactly ' + fields.join(', ');
  const checks = [];
  checks.push(pattern(st.vehicleId, HEX16, 'vehicleId', '32 lowercase hex characters'));
  checks.push(textProblem(st.note, NOTE_MAX, 'note', false));
  if (type === 'register') {
    checks.push(identProblem(st.vin, 'vin'));
    checks.push(enumProblem(st.vehicleClass, CLASSES, 'vehicleClass'));
    checks.push(textProblem(st.make, LABEL_MAX, 'make', true));
    checks.push(textProblem(st.model, LABEL_MAX, 'model', true));
    checks.push(intProblem(st.year, MIN_YEAR, MAX_YEAR, 'year'));
    checks.push(codeProblem(st.jurisdiction, 'jurisdiction'));
    checks.push(textProblem(st.plate, LABEL_MAX, 'plate', false));
    checks.push(pattern(st.ownerKeyId, HEX32, 'ownerKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.registrarKeyId, HEX32, 'registrarKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.registrarLabel, LABEL_MAX, 'registrarLabel', false));
    checks.push(timeProblem(st.registeredAt, 'registeredAt'));
  } else if (type === 'inspect') {
    checks.push(refProblem(st.vehicleRef, 'vehicleRef'));
    checks.push(enumProblem(st.outcome, OUTCOMES, 'outcome'));
    checks.push(intProblem(st.odometerKm, 0, MAX_ODOMETER_KM, 'odometerKm'));
    checks.push(pattern(st.inspectorKeyId, HEX32, 'inspectorKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.inspectorLabel, LABEL_MAX, 'inspectorLabel', false));
    checks.push(timeProblem(st.inspectedAt, 'inspectedAt'));
  } else if (type === 'transfer') {
    checks.push(refProblem(st.vehicleRef, 'vehicleRef'));
    checks.push(pattern(st.fromKeyId, HEX32, 'fromKeyId', '64 lowercase hex characters'));
    checks.push(pattern(st.toKeyId, HEX32, 'toKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.toLabel, LABEL_MAX, 'toLabel', false));
    checks.push(timeProblem(st.transferredAt, 'transferredAt'));
    if (!checks.some(Boolean) && st.fromKeyId === st.toKeyId) checks.push('the receiving key must differ from the sending key');
  } else {
    checks.push(refProblem(st.vehicleRef, 'vehicleRef'));
    checks.push(pattern(st.registrarKeyId, HEX32, 'registrarKeyId', '64 lowercase hex characters'));
    checks.push(textProblem(st.reason, LABEL_MAX, 'reason', true));
    checks.push(timeProblem(st.deregisteredAt, 'deregisteredAt'));
  }
  return checks.find(Boolean) || null;
}

function field(buf) {
  if (buf.length > 0xffff) reject('a signed field is too long');
  const len = Buffer.alloc(2);
  len.writeUInt16BE(buf.length);
  return Buffer.concat([len, buf]);
}

const ascii = (s) => field(Buffer.from(s, 'ascii'));
const utf8 = (s) => field(Buffer.from(s, 'utf8'));
const hex = (s) => field(Buffer.from(s, 'hex'));

function u64(n) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return field(b);
}

function payload(type, st) {
  const parts = [MAGIC, Buffer.from([VERSION]), ascii(type), hex(st.vehicleId)];
  if (type === 'register') {
    parts.push(utf8(st.vin), ascii(st.vehicleClass), utf8(st.make), utf8(st.model), u64(st.year), ascii(st.jurisdiction), utf8(st.plate), hex(st.ownerKeyId), hex(st.registrarKeyId), utf8(st.registrarLabel), ascii(st.registeredAt));
  } else if (type === 'inspect') {
    parts.push(hex(st.vehicleRef), ascii(st.outcome), u64(st.odometerKm), hex(st.inspectorKeyId), utf8(st.inspectorLabel), ascii(st.inspectedAt));
  } else if (type === 'transfer') {
    parts.push(hex(st.vehicleRef), hex(st.fromKeyId), hex(st.toKeyId), utf8(st.toLabel), ascii(st.transferredAt));
  } else {
    parts.push(hex(st.vehicleRef), hex(st.registrarKeyId), utf8(st.reason), ascii(st.deregisteredAt));
  }
  parts.push(utf8(st.note));
  return Buffer.concat(parts);
}

function decodeBase64(value, bytes, what) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes / 3) * 4) fail(what + ' must be base64 of ' + bytes + ' bytes');
  const raw = Buffer.from(value, 'base64');
  if (raw.toString('base64') !== value || raw.length !== bytes) fail(what + ' is not canonical base64 of ' + bytes + ' bytes');
  return raw;
}

function exactKeys(obj, required, optional, where) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) fail(where + ' must be an object');
  const allowed = new Set(required.concat(optional));
  for (const k of Object.keys(obj)) if (!allowed.has(k)) fail(where + ' holds an unexpected field');
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(obj, k)) fail(where + ' is missing ' + k);
}

function plainCopy(value, depth) {
  const d = depth === undefined ? 0 : depth;
  if (d > 6) throw new Error('nested too deeply');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('not a finite number');
    return value;
  }
  if (typeof value !== 'object') throw new Error('not plain data');
  const proto = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (proto !== Array.prototype) throw new Error('not a plain array');
    if (value.length > 4096) throw new Error('a list is too long');
    const out = [];
    for (let i = 0; i < value.length; i += 1) {
      const desc = Object.getOwnPropertyDescriptor(value, i);
      if (!desc || !('value' in desc)) throw new Error('not plain data');
      out.push(plainCopy(desc.value, d + 1));
    }
    return out;
  }
  if (proto !== Object.prototype && proto !== null) throw new Error('not a plain object');
  const out = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') throw new Error('not plain data');
    const desc = Object.getOwnPropertyDescriptor(value, key);
    if (!('value' in desc) || !desc.enumerable) throw new Error('not plain data');
    Object.defineProperty(out, key, { value: plainCopy(desc.value, d + 1), enumerable: true, writable: true, configurable: true });
  }
  return out;
}

function parse(envelope) {
  exactKeys(envelope, ['format', 'type', 'algorithm', 'signer', 'statement', 'signature'], ['anchor'], 'the envelope');
  if (envelope.format !== FORMAT) fail('format must be ' + FORMAT);
  if (envelope.algorithm !== ALGORITHM) fail('algorithm must be ' + ALGORITHM);
  if (!TYPES.includes(envelope.type)) fail('type must be one of ' + TYPES.join(', '));
  exactKeys(envelope.signer, ['id', 'publicKey'], [], 'signer');
  if (typeof envelope.signer.id !== 'string' || !HEX32.test(envelope.signer.id)) fail('signer.id must be 64 lowercase hex characters');
  const publicKey = decodeBase64(envelope.signer.publicKey, PUBLIC_KEY_BYTES, 'signer.publicKey');
  let statement;
  try {
    statement = plainCopy(envelope.statement);
  } catch (e) {
    fail('the statement is not plain data');
  }
  const problem = statementProblem(envelope.type, statement);
  if (problem) fail(problem);
  const signature = decodeBase64(envelope.signature, SIGNATURE_BYTES, 'signature');
  const anchor = Object.prototype.hasOwnProperty.call(envelope, 'anchor') ? envelope.anchor : undefined;
  return { type: envelope.type, signerId: envelope.signer.id, publicKey, statement, signature, anchor };
}

function encoded(parsed) {
  return payload(parsed.type, parsed.statement);
}

function refOf(parsed) {
  return sha3(REF_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature).toString('hex');
}

function anchorDigest(parsed) {
  return sha3(ANCHOR_DOMAIN, Buffer.from([0]), encoded(parsed), parsed.signature);
}

module.exports = {
  FORMAT, ALGORITHM, KIND, TYPES, FIELDS, CLASSES, OUTCOMES, PUBLIC_KEY_BYTES, SIGNATURE_BYTES, LABEL_MAX, NOTE_MAX, REF_MAX, MAX_ODOMETER_KM, MIN_YEAR, MAX_YEAR,
  sha3, keyIdOf, vehicleRefOf, textProblem, timeProblem, statementProblem, payload, encoded, parse, refOf, anchorDigest, reject, plainCopy,
};
