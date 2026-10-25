// End-to-end crypto on top of Web Crypto. Runs in browsers and in Node (for tests).
//
//   password --PBKDF2--> master --HKDF--> authKey  (sent to the server as the login secret)
//                                  \--HKDF--> wrapKey  (encrypts the identity private key; never leaves the client)
//
//   direct chat key = HKDF(ECDH(me, peer), "emerchat/direct/<chatId>")
//   group chat key  = random 32 bytes per epoch, wrapped for each member with
//                     HKDF(ECDH(wrapper, member), "emerchat/groupwrap/<epoch>/<memberId>")
//   messages        = AES-256-GCM, AAD binds chat, sender and epoch.
//   attachments     = AES-256-GCM under a random per-file key; the key travels
//                     inside the (encrypted) message that references the file.

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const PBKDF2_ITERATIONS = 600_000;
const EC = { name: 'ECDH', namedCurve: 'P-256' };

export function b64(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function unb64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return globalThis.crypto.getRandomValues(new Uint8Array(n));
}

async function hkdfBase(secret) {
  return subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits', 'deriveKey']);
}

function hkdfParams(info) {
  return { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: enc.encode(info) };
}

async function aesFromHkdf(base, info) {
  return subtle.deriveKey(hkdfParams(info), base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}

async function seal(key, plaintext, aad) {
  const iv = randomBytes(12);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: enc.encode(aad) }, key, plaintext);
  return { ciphertext: b64(ct), iv: b64(iv) };
}

async function open(key, ciphertextB64, ivB64, aad) {
  return new Uint8Array(await subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(ivB64), additionalData: enc.encode(aad) }, key, unb64(ciphertextB64)));
}

/** Derives the login secret and the key-wrapping key from a password. */
export async function deriveLoginKeys(password, kdfSaltB64, iterations = PBKDF2_ITERATIONS) {
  const pw = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const master = await subtle.deriveBits(
    { name: 'PBKDF2', salt: unb64(kdfSaltB64), iterations, hash: 'SHA-256' }, pw, 256);
  const base = await hkdfBase(master);
  const authKey = await subtle.deriveBits(hkdfParams('emerchat/auth'), base, 256);
  const wrapKey = await aesFromHkdf(base, 'emerchat/wrap');
  return { authKey: b64(authKey), wrapKey };
}

async function importPrivate(pkcs8) {
  return subtle.importKey('pkcs8', pkcs8, EC, false, ['deriveBits']);
}

/** Creates an identity key pair; the private key is returned non-extractable and also wrapped for upload. */
export async function createIdentity(wrapKey) {
  const kp = await subtle.generateKey(EC, true, ['deriveBits']);
  const publicKey = b64(await subtle.exportKey('raw', kp.publicKey));
  const pkcs8 = await subtle.exportKey('pkcs8', kp.privateKey);
  const { ciphertext, iv } = await seal(wrapKey, pkcs8, 'emerchat/identity');
  return { publicKey, wrappedPrivateKey: ciphertext, wrapIv: iv, privateKey: await importPrivate(pkcs8) };
}

export async function unwrapIdentity(wrapKey, wrappedPrivateKeyB64, wrapIvB64) {
  const pkcs8 = await open(wrapKey, wrappedPrivateKeyB64, wrapIvB64, 'emerchat/identity');
  return importPrivate(pkcs8);
}

const publicKeyCache = new Map();

async function importPublic(publicKeyB64) {
  let k = publicKeyCache.get(publicKeyB64);
  if (!k) {
    k = subtle.importKey('raw', unb64(publicKeyB64), EC, false, []);
    publicKeyCache.set(publicKeyB64, k);
  }
  return k;
}

async function pairwiseKey(privateKey, peerPublicKeyB64, info) {
  const pub = await importPublic(peerPublicKeyB64);
  const shared = await subtle.deriveBits({ name: 'ECDH', public: pub }, privateKey, 256);
  return aesFromHkdf(await hkdfBase(shared), info);
}

/** The symmetric key for a 1:1 chat; both sides derive the same one. */
export function directChatKey(privateKey, peerPublicKeyB64, chatId) {
  return pairwiseKey(privateKey, peerPublicKeyB64, `emerchat/direct/${chatId}`);
}

export function newGroupKey() {
  return randomBytes(32);
}

export async function wrapGroupKey(privateKey, memberPublicKeyB64, rawKey, epoch, memberId) {
  const info = `emerchat/groupwrap/${epoch}/${memberId}`;
  const k = await pairwiseKey(privateKey, memberPublicKeyB64, info);
  const { ciphertext, iv } = await seal(k, rawKey, info);
  return { userId: memberId, epoch, wrappedKey: ciphertext, iv };
}

export async function unwrapGroupKey(privateKey, wrapperPublicKeyB64, wrappedKeyB64, ivB64, epoch, myId) {
  const info = `emerchat/groupwrap/${epoch}/${myId}`;
  const k = await pairwiseKey(privateKey, wrapperPublicKeyB64, info);
  return open(k, wrappedKeyB64, ivB64, info);
}

export function importGroupKey(rawKey) {
  return subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

export function messageAAD(chatId, senderId, epoch) {
  return `emerchat/msg/${chatId}/${senderId}/${epoch}`;
}

export async function encryptMessage(key, payload, aad) {
  return seal(key, enc.encode(JSON.stringify(payload)), aad);
}

export async function decryptMessage(key, ciphertextB64, ivB64, aad) {
  return JSON.parse(dec.decode(await open(key, ciphertextB64, ivB64, aad)));
}

const FILE_AAD = enc.encode('emerchat/file');

/** Encrypts file bytes under a fresh key. Upload `data`; send `key` and `iv` in the message. */
export async function encryptFile(bytes) {
  const raw = randomBytes(32);
  const key = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  const iv = randomBytes(12);
  const data = await subtle.encrypt({ name: 'AES-GCM', iv, additionalData: FILE_AAD }, key, bytes);
  return { data: new Uint8Array(data), key: b64(raw), iv: b64(iv) };
}

export async function decryptFile(data, keyB64, ivB64) {
  const key = await subtle.importKey('raw', unb64(keyB64), 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: unb64(ivB64), additionalData: FILE_AAD }, key, data));
}

/** A 60-digit number both parties can compare to detect a swapped public key. */
export async function safetyNumber(publicKeyA, publicKeyB) {
  const [x, y] = [publicKeyA, publicKeyB].sort();
  const digest = new Uint8Array(await subtle.digest('SHA-512', enc.encode(`emerchat/safety/${x}/${y}`)));
  const groups = [];
  for (let i = 0; i < 12; i++) {
    let n = 0;
    for (let j = 0; j < 5; j++) n = n * 256 + digest[i * 5 + j];
    groups.push(String(n % 100000).padStart(5, '0'));
  }
  return groups;
}
