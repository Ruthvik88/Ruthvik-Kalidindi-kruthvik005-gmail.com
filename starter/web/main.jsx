import React, { useCallback, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { api, setToken, login, refreshSession, switchToken, fetchMe } from './api.js';

// ---------------------------------------------------------------------------
// Permission helpers. Everything here consumes the SERVER-resolved permission
// maps (`effect: 'allow' | 'deny'`). There is no role-to-permission table in
// this file: if the server says deny, the element is absent from the DOM.
// ---------------------------------------------------------------------------
const allows = (perms, p) => perms?.[p]?.effect === 'allow';
const allowsAny = (perms, list) => list.some((p) => allows(perms, p));
const permAttrs = (p) => ({ 'data-permission': p, 'data-state': 'unlocked' });

// Per-org identity: the shell background must measurably differ per org
// (asserted via getComputedStyle). Unknown themes fall back to slate.
const THEMES = {
  cobalt: '#1e40af',
  amber: '#b45309',
  emerald: '#047857',
  crimson: '#b91c1c',
  violet: '#6d28d9',
  teal: '#0f766e',
  rose: '#be123c',
  slate: '#475569',
};
const themeColor = (t) => THEMES[t] ?? THEMES.slate;

const DOCUMENTED_ROLES = ['owner', 'admin', 'operator', 'auditor', 'viewer'];

function ErrorMessage({ error, testid }) {
  if (!error) return null;
  return (
    <div data-testid={testid ?? 'page-error'} data-error-code={error.code ?? 'UNKNOWN'} role="alert" style={styles.error}>
      {error.message}
      {error.reason ? ` (${error.reason})` : ''}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sign-in
// ---------------------------------------------------------------------------
function LoginPage({ onDone, notice }) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e?.preventDefault();
    setError(null); // cleared on attempt; set again below on failure
    if (!email.trim() || !password) {
      setError({ code: 'VALIDATION', message: 'Email and password are required.' });
      return;
    }
    setBusy(true);
    try {
      const res = await login(email.trim(), password);
      setToken(res.token);
      const me = await fetchMe();
      onDone(me);
    } catch (err) {
      // Render the server's answer verbatim: wrong password and unknown
      // account read identically here by server design (no oracle).
      setError({ code: err.code, message: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <main style={styles.center}>
      <form data-testid="login-form" onSubmit={submit} style={styles.card}>
        <h1 style={{ margin: '0 0 12px' }}>RemoteOps</h1>
        {notice ? <p style={styles.notice}>{notice}</p> : null}
        <label style={styles.label}>
          Email
          <input data-testid="login-email" value={email} onChange={(e) => setEmail(e.target.value)} style={styles.input} autoComplete="username" />
        </label>
        <label style={styles.label}>
          Password
          <input data-testid="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={styles.input} autoComplete="current-password" />
        </label>
        <ErrorMessage error={error} testid="login-error" />
        <button data-testid="login-submit" type="submit" disabled={busy} style={styles.primary}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Invite accept (public route /invite/:token)
// ---------------------------------------------------------------------------
function InvitePage({ token }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);

  useEffect(() => {
    api('GET', `/v1/invites/${token}`, { auth: false })
      .then(setInvite)
      .catch((err) => setError(err));
  }, [token]);

  const submit = async (e) => {
    e?.preventDefault();
    try {
      await api('POST', `/v1/invites/${token}/accept`, { body: { name, password }, auth: false });
      setDone(true);
    } catch (err) {
      setError(err);
    }
  };

  if (done) {
    return (
      <LoginPage
        onDone={() => {
          window.location.assign('/');
        }}
        notice="Account ready — sign in with your new password."
      />
    );
  }
  if (error) {
    return (
      <main style={styles.center}>
        <div style={styles.card}>
          <h1 style={{ margin: '0 0 8px' }}>Invitation unavailable</h1>
          <div data-testid="invite-error" role="alert" style={styles.error}>
            {error.message}
          </div>
        </div>
      </main>
    );
  }
  if (!invite) return <main style={styles.center}>Loading invitation…</main>;
  return (
    <main style={styles.center}>
      <form data-testid="invite-form" onSubmit={submit} style={styles.card}>
        <h1 style={{ margin: '0 0 8px' }}>Join {invite.orgName}</h1>
        <p>
          Role: <span data-testid="invite-role">{invite.role}</span>
        </p>
        <label style={styles.label}>
          Email
          <input data-testid="invite-email" value={invite.email} readOnly style={styles.input} />
        </label>
        <label style={styles.label}>
          Name
          <input data-testid="invite-name" value={name} onChange={(e) => setName(e.target.value)} style={styles.input} autoComplete="name" />
        </label>
        <label style={styles.label}>
          Password
          <input data-testid="invite-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} style={styles.input} autoComplete="new-password" />
        </label>
        <button data-testid="invite-submit" type="submit" style={styles.primary}>
          Accept invitation
        </button>
      </form>
    </main>
  );
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------
function DeviceRow({ device, onChanged, setPageError, goSessions }) {
  const p = device.permissions ?? {};
  const [note, setNote] = useState(null);

  const run = async (fn) => {
    setNote(null);
    try {
      await fn();
      await onChanged();
    } catch (err) {
      setPageError(err);
    }
  };

  const startSession = (mode) =>
    run(async () => {
      await api('POST', `/v1/orgs/${device.orgId}/sessions`, { body: { deviceId: device.id, mode } });
      goSessions();
    });

  return (
    <tr data-testid="device-row" data-device-id={device.id}>
      <td>{device.name}</td>
      <td>{device.kind}</td>
      <td>{device.online ? 'online' : 'offline'}</td>
      <td style={styles.actions}>
        {allows(p, 'device:view') ? (
          <button data-testid="start-view" {...permAttrs('device:view')} onClick={() => startSession('view')}>View</button>
        ) : null}
        {allows(p, 'device:control') ? (
          <button data-testid="start-control" {...permAttrs('device:control')} onClick={() => startSession('control')}>Control</button>
        ) : null}
        {allows(p, 'device:terminal') ? (
          <button data-testid="start-terminal" {...permAttrs('device:terminal')} onClick={() => startSession('terminal')}>Terminal</button>
        ) : null}
        {allows(p, 'device:file_transfer') ? (
          <button data-testid="transfer-files" {...permAttrs('device:file_transfer')} onClick={() => setNote('Transfer queued (demo).')}>Transfer files</button>
        ) : null}
        {allows(p, 'device:update') ? (
          <button
            data-testid="rename-device"
            {...permAttrs('device:update')}
            onClick={() => {
              const name = window.prompt('New device name', device.name);
              if (name) run(() => api('PATCH', `/v1/orgs/${device.orgId}/devices/${device.id}`, { body: { name } }));
            }}
          >
            Rename
          </button>
        ) : null}
        {allows(p, 'device:provision') ? (
          <button
            data-testid="decommission-device"
            {...permAttrs('device:provision')}
            onClick={() => {
              if (window.confirm(`Decommission ${device.name}?`)) {
                run(() => api('DELETE', `/v1/orgs/${device.orgId}/devices/${device.id}`));
              }
            }}
          >
            Decommission
          </button>
        ) : null}
        {note ? <span style={styles.note}>{note}</span> : null}
      </td>
    </tr>
  );
}

function DevicesPage({ session, setPageError, goSessions }) {
  const [devices, setDevices] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [kind, setKind] = useState('linux');

  const load = useCallback(async () => {
    try {
      const res = await api('GET', `/v1/orgs/${session.org.id}/devices`);
      const withOrg = res.devices.map((d) => ({ ...d, orgId: session.org.id }));
      setDevices(withOrg);
    } catch (err) {
      setPageError(err);
      setDevices([]);
    }
  }, [session, setPageError]);

  useEffect(() => {
    load();
  }, [load]);

  if (devices === null) return <p>Loading devices…</p>;
  return (
    <section>
      <h2>Devices</h2>
      {allows(session.permissions, 'device:provision') ? (
        showAdd ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                await api('POST', `/v1/orgs/${session.org.id}/devices`, { body: { name, kind } });
                setName('');
                setShowAdd(false);
                await load();
              } catch (err) {
                setPageError(err);
              }
            }}
            style={styles.inlineForm}
          >
            <input aria-label="device name" value={name} onChange={(e) => setName(e.target.value)} placeholder="name" style={styles.input} />
            <select aria-label="device kind" value={kind} onChange={(e) => setKind(e.target.value)}>
              {['macos', 'windows', 'linux', 'android', 'ios'].map((k) => (
                <option key={k} value={k}>{k}</option>
              ))}
            </select>
            <button data-testid="add-device" {...permAttrs('device:provision')} type="submit">Add device</button>
          </form>
        ) : (
          <button data-testid="add-device" {...permAttrs('device:provision')} onClick={() => setShowAdd(true)}>Add device</button>
        )
      ) : null}
      {devices.length === 0 ? (
        <p data-testid="devices-empty">No devices yet.</p>
      ) : (
        <table style={styles.table}>
          <thead>
            <tr><th>Name</th><th>Kind</th><th>Status</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <DeviceRow key={d.id} device={d} onChanged={load} setPageError={setPageError} goSessions={goSessions} />
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

// ---------------------------------------------------------------------------
// People
// ---------------------------------------------------------------------------
function PeoplePage({ session, setPageError }) {
  const [members, setMembers] = useState(null);
  const [showInvite, setShowInvite] = useState(false);
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('viewer');
  const [inviteToken, setInviteToken] = useState(null);

  const load = useCallback(async () => {
    try {
      const res = await api('GET', `/v1/orgs/${session.org.id}/members`);
      setMembers(res.members);
    } catch (err) {
      setPageError(err);
      setMembers([]);
    }
  }, [session, setPageError]);

  useEffect(() => {
    load();
  }, [load]);

  const mutate = async (fn) => {
    try {
      await fn();
      await load();
    } catch (err) {
      setPageError(err);
    }
  };

  const roleOptions = Array.from(new Set([...DOCUMENTED_ROLES, ...(members ?? []).map((m) => m.role)]));
  if (members === null) return <p>Loading people…</p>;
  return (
    <section>
      <h2>People</h2>
      {allows(session.permissions, 'user:invite') ? (
        showInvite ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                const res = await api('POST', `/v1/orgs/${session.org.id}/invites`, { body: { email, role } });
                setInviteToken(res.inviteToken);
                setEmail('');
                await load();
              } catch (err) {
                setPageError(err);
              }
            }}
            style={styles.inlineForm}
          >
            <input aria-label="invite email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="email" style={styles.input} />
            <select aria-label="invite role" value={role} onChange={(e) => setRole(e.target.value)}>
              {roleOptions.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
            <button data-testid="invite-submit" type="submit">Send invite</button>
            {inviteToken ? <code style={styles.note}>{inviteToken}</code> : null}
          </form>
        ) : (
          <button data-testid="invite-user" {...permAttrs('user:invite')} onClick={() => setShowInvite(true)}>Invite</button>
        )
      ) : null}
      <table style={styles.table}>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
        <tbody>
          {members.map((m) => (
            <tr key={m.userId} data-testid="user-row" data-user-id={m.userId}>
              <td>{m.name}</td>
              <td>{m.email}</td>
              <td>
                {allows(session.permissions, 'user:role:update') ? (
                  <select
                    data-testid="role-select"
                    {...permAttrs('user:role:update')}
                    value={m.role}
                    onChange={(e) =>
                      mutate(() => api('PATCH', `/v1/orgs/${session.org.id}/members/${m.userId}`, { body: { role: e.target.value } }))
                    }
                  >
                    {roleOptions.map((r) => (
                      <option key={r} value={r}>{r}</option>
                    ))}
                  </select>
                ) : (
                  m.role
                )}
              </td>
              <td>{m.status}</td>
              <td style={styles.actions}>
                {allows(session.permissions, 'user:remove') ? (
                  m.status === 'suspended' ? (
                    <button
                      data-testid="suspend-user"
                      {...permAttrs('user:remove')}
                      onClick={() => mutate(() => api('DELETE', `/v1/orgs/${session.org.id}/members/${m.userId}/suspend`))}
                    >
                      Reinstate
                    </button>
                  ) : (
                    <button
                      data-testid="suspend-user"
                      {...permAttrs('user:remove')}
                      onClick={() => mutate(() => api('POST', `/v1/orgs/${session.org.id}/members/${m.userId}/suspend`))}
                    >
                      Suspend
                    </button>
                  )
                ) : null}
                {allows(session.permissions, 'user:remove') ? (
                  <button
                    data-testid="remove-user"
                    {...permAttrs('user:remove')}
                    onClick={() => {
                      if (window.confirm(`Remove ${m.email}?`)) {
                        mutate(() => api('DELETE', `/v1/orgs/${session.org.id}/members/${m.userId}`));
                      }
                    }}
                  >
                    Remove
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------
function GrantsPage({ session, setPageError }) {
  const [grants, setGrants] = useState(null);
  const [members, setMembers] = useState([]);
  const [devices, setDevices] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [userId, setUserId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  const [effect, setEffect] = useState('allow');
  const [checked, setChecked] = useState({});
  const permissionKeys = Object.keys(session.permissions);

  const load = useCallback(async () => {
    try {
      const [g, m, d] = await Promise.all([
        api('GET', `/v1/orgs/${session.org.id}/grants`),
        api('GET', `/v1/orgs/${session.org.id}/members`),
        api('GET', `/v1/orgs/${session.org.id}/devices`),
      ]);
      setGrants(g.grants);
      setMembers(m.members);
      setDevices(d.devices);
      if (!userId && m.members.length > 0) setUserId(m.members[0].userId);
    } catch (err) {
      setPageError(err);
      setGrants([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, setPageError]);

  useEffect(() => {
    load();
  }, [load]);

  if (grants === null) return <p>Loading grants…</p>;
  return (
    <section>
      <h2>Grants</h2>
      {allows(session.permissions, 'grant:create') ? (
        showForm ? (
          <form
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                const permissions = Object.keys(checked).filter((k) => checked[k]);
                await api('POST', `/v1/orgs/${session.org.id}/grants`, {
                  body: { userId, deviceId: deviceId || null, effect, permissions },
                });
                setChecked({});
                setShowForm(false);
                await load();
              } catch (err) {
                setPageError(err);
              }
            }}
            style={styles.form}
          >
            <label style={styles.label}>
              User
              <select data-testid="grant-user" value={userId} onChange={(e) => setUserId(e.target.value)} style={styles.input}>
                {members.map((m) => (
                  <option key={m.userId} value={m.userId}>{m.email} ({m.role})</option>
                ))}
              </select>
            </label>
            <label style={styles.label}>
              Device
              <select data-testid="grant-device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} style={styles.input}>
                <option value="">Entire org</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            </label>
            <label style={styles.label}>
              Effect
              <select data-testid="grant-effect" value={effect} onChange={(e) => setEffect(e.target.value)} style={styles.input}>
                <option value="allow">allow</option>
                <option value="deny">deny</option>
              </select>
            </label>
            <fieldset style={styles.fieldset}>
              <legend>Permissions</legend>
              {permissionKeys.map((k) => (
                <label key={k} style={styles.check}>
                  <input
                    type="checkbox"
                    data-permission-key={k}
                    checked={!!checked[k]}
                    onChange={(e) => setChecked((c) => ({ ...c, [k]: e.target.checked }))}
                  />
                  {k}
                </label>
              ))}
            </fieldset>
            <button data-testid="grant-submit" type="submit" style={styles.primary}>Create grant</button>
          </form>
        ) : (
          <button data-testid="new-grant" {...permAttrs('grant:create')} onClick={() => setShowForm(true)}>New grant</button>
        )
      ) : null}
      <table style={styles.table}>
        <thead><tr><th>User</th><th>Device</th><th>Effect</th><th>Permissions</th><th>Actions</th></tr></thead>
        <tbody>
          {grants.map((g) => (
            <tr key={g.id} data-testid="grant-row" data-effect={g.effect}>
              <td>{g.userId}</td>
              <td>{g.deviceId ?? 'org-wide'}</td>
              <td>{g.effect}</td>
              <td>{g.permissions.join(', ')}</td>
              <td>
                {allows(session.permissions, 'grant:revoke') ? (
                  <button
                    data-testid="revoke-grant"
                    {...permAttrs('grant:revoke')}
                    onClick={async () => {
                      try {
                        await api('DELETE', `/v1/orgs/${session.org.id}/grants/${g.id}`);
                        await load();
                      } catch (err) {
                        setPageError(err);
                      }
                    }}
                  >
                    Revoke
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
function SessionsPage({ session, setPageError }) {
  const [sessions, setSessions] = useState(null);
  const [devices, setDevices] = useState([]);
  const [deviceId, setDeviceId] = useState('');
  const [mode, setMode] = useState('view');

  const load = useCallback(async () => {
    try {
      const [s, d] = await Promise.all([
        api('GET', `/v1/orgs/${session.org.id}/sessions`),
        api('GET', `/v1/orgs/${session.org.id}/devices`).catch(() => ({ devices: [] })),
      ]);
      setSessions(s.sessions);
      setDevices(d.devices);
      if (!deviceId && d.devices.length > 0) setDeviceId(d.devices[0].id);
    } catch (err) {
      setPageError(err);
      setSessions([]);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session, setPageError]);

  useEffect(() => {
    load();
  }, [load]);

  if (sessions === null) return <p>Loading sessions…</p>;
  return (
    <section>
      <h2>Sessions</h2>
      {allows(session.permissions, 'session:start') ? (
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              await api('POST', `/v1/orgs/${session.org.id}/sessions`, { body: { deviceId, mode } });
              await load();
            } catch (err) {
              setPageError(err);
            }
          }}
          style={styles.inlineForm}
        >
          <select aria-label="session device" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
          <select aria-label="session mode" value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="view">view</option>
            <option value="control">control</option>
            <option value="terminal">terminal</option>
          </select>
          <button data-testid="new-session" {...permAttrs('session:start')} type="submit">Start session</button>
        </form>
      ) : null}
      <table style={styles.table}>
        <thead><tr><th>ID</th><th>Device</th><th>Mode</th><th>State</th><th>Actions</th></tr></thead>
        <tbody>
          {sessions.map((s) => {
            const own = s.user_id === session.user.id;
            const mayStop = own || allows(session.permissions, 'session:terminate');
            return (
              <tr key={s.id} data-testid="session-row" data-session-id={s.id}>
                <td>{s.id}</td>
                <td>{s.device_id}</td>
                <td>{s.mode}</td>
                <td>{s.state}</td>
                <td>
                  {mayStop && s.state === 'active' ? (
                    <button
                      data-testid="stop-session"
                      {...(own ? { 'data-state': 'unlocked' } : permAttrs('session:terminate'))}
                      onClick={async () => {
                        try {
                          await api('DELETE', `/v1/sessions/${s.id}`);
                          await load();
                        } catch (err) {
                          setPageError(err);
                        }
                      }}
                    >
                      Stop
                    </button>
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Audit + Admin
// ---------------------------------------------------------------------------
function AuditPage({ session, setPageError }) {
  const [events, setEvents] = useState(null);
  useEffect(() => {
    api('GET', `/v1/orgs/${session.org.id}/audit?limit=100`)
      .then((res) => setEvents(res.events))
      .catch((err) => {
        setPageError(err);
        setEvents([]);
      });
  }, [session, setPageError]);
  if (events === null) return <p>Loading audit…</p>;
  return (
    <section>
      <h2>Audit</h2>
      <table style={styles.table}>
        <thead><tr><th>When</th><th>Actor</th><th>Action</th><th>Result</th></tr></thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id} data-testid="audit-row">
              <td>{e.at}</td>
              <td>{e.actor_id ?? '—'}</td>
              <td>{e.action}{e.reason_code ? ` (${e.reason_code})` : ''}</td>
              <td>{e.result}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

function AdminPage({ session, setPageError, refreshMe, switchToOrg }) {
  const rename = async () => {
    const name = window.prompt('New organization name', session.org.name);
    if (!name) return;
    try {
      await api('PATCH', `/v1/orgs/${session.org.id}`, { body: { name } });
      await refreshMe();
    } catch (err) {
      setPageError(err);
    }
  };
  const remove = async () => {
    if (!window.confirm(`Delete ${session.org.name}?`)) return;
    const fallback = session.orgs.find((o) => o.id !== session.org.id);
    try {
      await api('DELETE', `/v1/orgs/${session.org.id}`);
      if (fallback) {
        await switchToOrg(fallback.id);
      } else {
        window.location.reload();
      }
    } catch (err) {
      setPageError(err);
    }
  };
  return (
    <section>
      <h2>Admin</h2>
      <div style={styles.actions}>
        {allows(session.permissions, 'org:update') ? (
          <button data-testid="rename-org" {...permAttrs('org:update')} onClick={rename}>Rename org</button>
        ) : null}
        {allows(session.permissions, 'org:delete') ? (
          <button data-testid="delete-org" {...permAttrs('org:delete')} onClick={remove}>Delete org</button>
        ) : null}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Shell + App
// ---------------------------------------------------------------------------
const NAV = [
  { key: 'devices', label: 'Devices', perm: ['device:list'] },
  { key: 'people', label: 'People', perm: ['user:read'] },
  { key: 'grants', label: 'Grants', perm: ['user:read'] },
  { key: 'sessions', label: 'Sessions', perm: ['session:view'] },
  { key: 'audit', label: 'Audit', perm: ['audit:read'] },
  { key: 'admin', label: 'Admin', perm: ['org:update', 'org:delete'] },
];

function Shell({ session, onSession, onSignOut }) {
  const [page, setPage] = useState('devices');
  const [pageError, setPageError] = useState(null);

  const refreshMe = async () => {
    onSession(await fetchMe());
  };
  const switchToOrg = async (orgId) => {
    const t = await switchToken(orgId);
    setToken(t.token);
    onSession(await fetchMe());
    setPage('devices');
    setPageError(null);
  };

  const createOrg = async () => {
    const name = window.prompt('Organization name');
    if (!name) return;
    try {
      const created = await api('POST', '/v1/orgs', { body: { name } });
      await switchToOrg(created.id);
    } catch (err) {
      setPageError(err);
    }
  };

  const visibleNav = NAV.filter((n) => allowsAny(session.permissions, n.perm));
  if (!visibleNav.some((n) => n.key === page)) {
    if (visibleNav.length > 0 && page !== visibleNav[0].key) setPage(visibleNav[0].key);
  }

  return (
    <div data-testid="app-shell" data-org-id={session.org.id} data-org-theme={session.org.theme} style={{ ...styles.shell, background: themeColor(session.org.theme) }}>
      <header style={styles.header}>
        <strong>RemoteOps</strong>
        <nav aria-label="organizations" style={styles.row}>
          {session.orgs.map((o) => (
            <button key={o.id} data-testid="org-option" data-org-id={o.id} onClick={() => switchToOrg(o.id)} style={o.id === session.org.id ? styles.currentOrg : undefined}>
              {o.name}
            </button>
          ))}
        </nav>
        <span data-testid="active-role">{session.role}</span>
        <button data-testid="create-org" onClick={createOrg}>New org</button>
        <button data-testid="sign-out" onClick={onSignOut}>Sign out</button>
      </header>
      <nav aria-label="sections" style={styles.row}>
        {visibleNav.map((n) => (
          <button key={n.key} data-testid={`nav-${n.key}`} onClick={() => { setPage(n.key); setPageError(null); }}>
            {n.label}
          </button>
        ))}
      </nav>
      <main style={styles.main}>
        <ErrorMessage error={pageError} />
        {page === 'devices' && <DevicesPage session={session} setPageError={setPageError} goSessions={() => setPage('sessions')} />}
        {page === 'people' && allows(session.permissions, 'user:read') && <PeoplePage session={session} setPageError={setPageError} />}
        {page === 'grants' && allows(session.permissions, 'user:read') && <GrantsPage session={session} setPageError={setPageError} />}
        {page === 'sessions' && allows(session.permissions, 'session:view') && <SessionsPage session={session} setPageError={setPageError} />}
        {page === 'audit' && allows(session.permissions, 'audit:read') && <AuditPage session={session} setPageError={setPageError} />}
        {page === 'admin' && allowsAny(session.permissions, ['org:update', 'org:delete']) && (
          <AdminPage session={session} setPageError={setPageError} refreshMe={refreshMe} switchToOrg={switchToOrg} />
        )}
      </main>
    </div>
  );
}

function App() {
  const [session, setSession] = useState(null);
  const [booted, setBooted] = useState(false);
  const [notice, setNotice] = useState(null);
  const inviteMatch = /^\/invite\/(.+)$/.exec(window.location.pathname);

  useEffect(() => {
    if (inviteMatch) {
      setBooted(true);
      return;
    }
    refreshSession()
      .then((t) => {
        setToken(t.token);
        return fetchMe();
      })
      .then((me) => {
        setSession(me);
        setBooted(true);
      })
      .catch(() => setBooted(true));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!booted) return <main style={styles.center}>Loading…</main>;
  if (inviteMatch) return <InvitePage token={decodeURIComponent(inviteMatch[1])} />;
  if (!session) {
    return (
      <LoginPage
        notice={notice}
        onDone={(me) => {
          setNotice(null);
          setSession(me);
        }}
      />
    );
  }
  return (
    <Shell
      session={session}
      onSession={setSession}
      onSignOut={() => {
        setToken(null);
        setSession(null);
        setNotice(null);
      }}
    />
  );
}

const styles = {
  shell: { minHeight: '100vh', color: '#fff', fontFamily: 'ui-sans-serif, system-ui, sans-serif' },
  header: { display: 'flex', gap: 12, alignItems: 'center', padding: '12px 16px', background: 'rgba(0,0,0,.35)', flexWrap: 'wrap' },
  row: { display: 'flex', gap: 8, alignItems: 'center', padding: '8px 16px', flexWrap: 'wrap' },
  main: { padding: '8px 16px 32px', color: '#111', background: '#f4f5f7', minHeight: '60vh' },
  center: { minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', fontFamily: 'ui-sans-serif, system-ui, sans-serif', background: '#1f2937', color: '#fff' },
  card: { background: '#fff', color: '#111', padding: 24, borderRadius: 8, minWidth: 320 },
  label: { display: 'block', margin: '8px 0' },
  input: { display: 'block', width: '100%', marginTop: 4, padding: 8, boxSizing: 'border-box' },
  primary: { marginTop: 12, padding: '8px 16px' },
  error: { background: '#fee2e2', color: '#991b1b', padding: 8, borderRadius: 4, margin: '8px 0' },
  notice: { background: '#dcfce7', color: '#166534', padding: 8, borderRadius: 4 },
  note: { fontSize: 12, opacity: 0.8, marginLeft: 8 },
  table: { borderCollapse: 'collapse', width: '100%', background: '#fff', marginTop: 8 },
  actions: { display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' },
  inlineForm: { display: 'flex', gap: 8, alignItems: 'center', margin: '8px 0', flexWrap: 'wrap' },
  form: { display: 'flex', flexDirection: 'column', gap: 8, maxWidth: 480, background: '#fff', padding: 12, margin: '8px 0' },
  fieldset: { border: '1px solid #ccc', display: 'flex', flexWrap: 'wrap', gap: 8 },
  check: { display: 'flex', gap: 4, alignItems: 'center', fontSize: 13 },
};

createRoot(document.getElementById('root')).render(<App />);
