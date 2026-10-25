// Keeps the (non-extractable) identity private key in IndexedDB so a page
// reload doesn't need the password. Script on the page can use the key but
// cannot export its bytes.

const DB = 'emerchat';
const STORE = 'keys';

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function run(mode, fn) {
  const db = await openDB();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      tx.oncomplete = () => resolve(req.result);
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

export async function saveKey(userId, privateKey) {
  try {
    await run('readwrite', (s) => s.put(privateKey, String(userId)));
  } catch (e) {
    console.warn('could not persist key', e);
  }
}

export async function loadKey(userId) {
  try {
    return (await run('readonly', (s) => s.get(String(userId)))) || null;
  } catch {
    return null;
  }
}

export async function clearKeys() {
  try {
    await run('readwrite', (s) => s.clear());
  } catch {
    // nothing to clear
  }
}
