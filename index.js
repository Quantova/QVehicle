// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

'use strict';

const V = require('./lib/vehicle');
const { verify } = require('./lib/verify');
const F = require('./lib/format');

module.exports = {
  generateKey: V.generateKey,
  publicKey: V.publicKey,
  keyId: V.keyId,
  describeKey: V.describeKey,
  vehicleRef: V.vehicleRef,
  register: V.register,
  inspect: V.inspect,
  transfer: V.transfer,
  deregister: V.deregister,
  anchor: V.anchor,
  complete: V.complete,
  verify,
  anchorDigest: (envelope) => F.anchorDigest(F.parse(envelope)).toString('hex'),
  recordRef: (envelope) => F.refOf(F.parse(envelope)),
  FORMAT: F.FORMAT,
  ALGORITHM: F.ALGORITHM,
  KIND: F.KIND,
  TYPES: F.TYPES,
  CLASSES: F.CLASSES,
  OUTCOMES: F.OUTCOMES,
  PUBLIC_KEY_BYTES: F.PUBLIC_KEY_BYTES,
  SIGNATURE_BYTES: F.SIGNATURE_BYTES,
};
