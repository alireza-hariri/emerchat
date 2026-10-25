// Run with: node --test web/test/*.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cx from '../js/crypto.js';

const ITER = 1000; // fast; production uses PBKDF2_ITERATIONS

async function identity(password = 'correct horse') {
  const salt = cx.b64(cx.randomBytes(16));
  const { authKey, wrapKey } = await cx.deriveLoginKeys(password, salt, ITER);
  const id = await cx.createIdentity(wrapKey);
  return { salt, authKey, wrapKey, ...id };
}

test('base64 round trip, including large buffers', () => {
  const data = Uint8Array.from({ length: 200_000 }, (_, i) => (i * 31) & 255);
  assert.deepEqual(cx.unb64(cx.b64(data)), data);
});

test('login keys are deterministic per password and salt', async () => {
  const salt = cx.b64(cx.randomBytes(16));
  const a = await cx.deriveLoginKeys('pw', salt, ITER);
  const b = await cx.deriveLoginKeys('pw', salt, ITER);
  const c = await cx.deriveLoginKeys('pw2', salt, ITER);
  assert.equal(a.authKey, b.authKey);
  assert.notEqual(a.authKey, c.authKey);
  assert.equal(cx.unb64(a.authKey).length, 32);
});

test('identity unwraps with the right password only', async () => {
  const id = await identity();
  assert.equal(cx.unb64(id.publicKey).length, 65);
  const { wrapKey } = await cx.deriveLoginKeys('correct horse', id.salt, ITER);
  const pk = await cx.unwrapIdentity(wrapKey, id.wrappedPrivateKey, id.wrapIv);
  assert.equal(pk.extractable, false);
  const wrong = await cx.deriveLoginKeys('wrong', id.salt, ITER);
  await assert.rejects(cx.unwrapIdentity(wrong.wrapKey, id.wrappedPrivateKey, id.wrapIv));
});

test('direct chat: both sides derive the same key', async () => {
  const alice = await identity(), bob = await identity();
  const ka = await cx.directChatKey(alice.privateKey, bob.publicKey, 7);
  const kb = await cx.directChatKey(bob.privateKey, alice.publicKey, 7);
  const aad = cx.messageAAD(7, 1, 0);
  const sealed = await cx.encryptMessage(ka, { t: 'hello 👋' }, aad);
  assert.deepEqual(await cx.decryptMessage(kb, sealed.ciphertext, sealed.iv, aad), { t: 'hello 👋' });

  // Different chat id => different key; wrong AAD (spoofed sender) fails.
  const other = await cx.directChatKey(bob.privateKey, alice.publicKey, 8);
  await assert.rejects(cx.decryptMessage(other, sealed.ciphertext, sealed.iv, aad));
  await assert.rejects(cx.decryptMessage(kb, sealed.ciphertext, sealed.iv, cx.messageAAD(7, 2, 0)));
});

test('a third party cannot derive the direct key', async () => {
  const alice = await identity(), bob = await identity(), eve = await identity();
  const ka = await cx.directChatKey(alice.privateKey, bob.publicKey, 1);
  const ke = await cx.directChatKey(eve.privateKey, alice.publicKey, 1);
  const aad = cx.messageAAD(1, 1, 0);
  const sealed = await cx.encryptMessage(ka, { t: 'secret' }, aad);
  await assert.rejects(cx.decryptMessage(ke, sealed.ciphertext, sealed.iv, aad));
});

test('group key wrap/unwrap per member', async () => {
  const alice = await identity(), bob = await identity(), carol = await identity();
  const raw = cx.newGroupKey();
  const forBob = await cx.wrapGroupKey(alice.privateKey, bob.publicKey, raw, 3, 22);
  assert.equal(forBob.userId, 22);
  assert.equal(forBob.epoch, 3);
  const got = await cx.unwrapGroupKey(bob.privateKey, alice.publicKey, forBob.wrappedKey, forBob.iv, 3, 22);
  assert.deepEqual(got, raw);
  // Carol can't use Bob's wrapped copy; wrong epoch fails too.
  await assert.rejects(cx.unwrapGroupKey(carol.privateKey, alice.publicKey, forBob.wrappedKey, forBob.iv, 3, 22));
  await assert.rejects(cx.unwrapGroupKey(bob.privateKey, alice.publicKey, forBob.wrappedKey, forBob.iv, 4, 22));

  const key = await cx.importGroupKey(got);
  const aad = cx.messageAAD(5, 22, 3);
  const sealed = await cx.encryptMessage(key, { t: 'hi group' }, aad);
  assert.deepEqual(await cx.decryptMessage(await cx.importGroupKey(raw), sealed.ciphertext, sealed.iv, aad), { t: 'hi group' });
});

test('safety number is symmetric and key-dependent', async () => {
  const a = await identity(), b = await identity(), c = await identity();
  const ab = await cx.safetyNumber(a.publicKey, b.publicKey);
  assert.deepEqual(ab, await cx.safetyNumber(b.publicKey, a.publicKey));
  assert.equal(ab.length, 12);
  assert.ok(ab.every((g) => /^\d{5}$/.test(g)));
  assert.notDeepEqual(ab, await cx.safetyNumber(a.publicKey, c.publicKey));
});

test('attachments round trip and reject tampering or the wrong key', async () => {
  const bytes = Uint8Array.from({ length: 5000 }, (_, i) => i & 255);
  const enc = await cx.encryptFile(bytes);
  assert.equal(enc.data.length, bytes.length + 16);
  assert.deepEqual(await cx.decryptFile(enc.data, enc.key, enc.iv), bytes);
  const other = await cx.encryptFile(bytes);
  await assert.rejects(cx.decryptFile(enc.data, other.key, enc.iv));
  const bad = enc.data.slice();
  bad[10] ^= 1;
  await assert.rejects(cx.decryptFile(bad, enc.key, enc.iv));
});
