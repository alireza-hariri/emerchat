export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export async function api(method, path, body, { signal } = {}) {
  const headers = { 'X-Emer': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    signal,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error || res.statusText);
  return data;
}

/** Sends raw bytes, reporting progress (0..1). XHR because fetch can't report upload progress. */
export function upload(method, path, body, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, path);
    xhr.setRequestHeader('X-Emer', '1');
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    xhr.responseType = 'json';
    if (onProgress) xhr.upload.onprogress = (e) => { if (e.lengthComputable) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      if (xhr.status < 300) resolve(xhr.response);
      else reject(new ApiError(xhr.status, xhr.response?.error || xhr.statusText || 'Upload failed'));
    };
    xhr.onerror = () => reject(new ApiError(0, 'Network error'));
    xhr.send(body);
  });
}

export async function download(path) {
  const res = await fetch(path, { credentials: 'same-origin' });
  if (!res.ok) throw new ApiError(res.status, res.status === 404 ? 'File not found' : res.statusText);
  return res.arrayBuffer();
}
