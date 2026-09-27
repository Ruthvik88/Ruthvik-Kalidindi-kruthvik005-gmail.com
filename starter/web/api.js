// API client. The access token lives in module memory only — never in
// localStorage, sessionStorage, or a readable cookie (D13). The refresh
// cookie is httpOnly; the browser attaches it to same-origin requests itself.

let token = null;

export function setToken(t) {
  token = t;
}

export async function api(method, path, { body, auth = true } = {}) {
  const headers = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth && token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const e = json?.error ?? {};
    throw {
      status: res.status,
      code: e.code ?? 'UNKNOWN',
      message: e.message ?? 'Request failed',
      reason: e.reason ?? null,
    };
  }
  return json;
}

export const login = (email, password) =>
  api('POST', '/v1/auth/login', { body: { email, password }, auth: false });

export const refreshSession = () => api('POST', '/v1/auth/refresh', { auth: false });

export const switchToken = (orgId) => api('POST', '/v1/auth/token', { body: { orgId } });

export const fetchMe = () => api('GET', '/v1/auth/me');
