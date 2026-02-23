const express = require('express');
const crypto = require('crypto');
const https = require('https');
const path = require('path');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ─── In-memory stores ────────────────────────────────────────────────────────
const pendingTokens = new Map(); // token -> { email, expires }
const sessions      = new Map(); // sessionId -> { email, expires, createdAt }
const loginLog      = [];        // { email, time, ip }

// ─── Rate limiting (3 requests / 10 min per email) ───────────────────────────
const rateLimits = new Map();
function isRateLimited(email) {
  const now = Date.now(), window = 10 * 60 * 1000, limit = 3;
  const times = (rateLimits.get(email) || []).filter(t => now - t < window);
  rateLimits.set(email, times);
  return times.length >= limit;
}
function recordRateLimit(email) {
  const times = rateLimits.get(email) || [];
  times.push(Date.now());
  rateLimits.set(email, times);
}

// ─── Email via Resend ─────────────────────────────────────────────────────────
function sendEmail(to, subject, html) {
  const apiKey = process.env.RESEND_API_KEY;
  const from   = process.env.RESEND_FROM || 'Post Generator <onboarding@resend.dev>';

  if (!apiKey) {
    console.log(`[EMAIL DEV] To: ${to} | Subject: ${subject}`);
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ from, to, subject, html });
    const req  = https.request({
      hostname: 'api.resend.com',
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, res => {
      let data = '';
      res.on('data', d => data += d);
      res.on('end', () => {
        if (res.statusCode >= 300) console.error(`[EMAIL ERROR] ${res.statusCode}: ${data}`);
        resolve();
      });
    });
    req.on('error', err => { console.error('[EMAIL ERROR]', err); resolve(); });
    req.write(body);
    req.end();
  });
}

// ─── Auth middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const sessionId = req.cookies?.session;
  const session   = sessionId && sessions.get(sessionId);

  if (!session || Date.now() > session.expires) {
    if (sessionId) sessions.delete(sessionId);
    res.clearCookie('session');
    return res.redirect('/');
  }

  // Rolling session — extend on each request
  session.expires = Date.now() + 7 * 24 * 60 * 60 * 1000;
  req.userEmail = session.email;
  next();
}

// ─── Routes ───────────────────────────────────────────────────────────────────

// Login page
app.get('/', (req, res) => {
  const sessionId = req.cookies?.session;
  if (sessionId && sessions.has(sessionId)) return res.redirect('/app');
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Request magic link
app.post('/api/magic', async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();

  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  if (isRateLimited(email)) {
    return res.status(429).json({ error: 'Too many requests. Wait a few minutes and try again.' });
  }

  recordRateLimit(email);

  const token   = crypto.randomBytes(32).toString('hex');
  const expires = Date.now() + 15 * 60 * 1000; // 15 min
  pendingTokens.set(token, { email, expires });

  const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
  const link    = `${baseUrl}/auth?token=${token}`;

  await sendEmail(email, 'Your login link — Post Generator', `
    <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
      <h2 style="color:#0a66c2;margin-bottom:8px">Post Generator</h2>
      <p style="color:#374151;margin-bottom:24px">Click the button below to log in. This link expires in 15 minutes and can only be used once.</p>
      <a href="${link}" style="display:inline-block;background:#0a66c2;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Log in</a>
      <p style="color:#9ca3af;font-size:12px;margin-top:24px">Or copy this URL:<br>${link}</p>
    </div>
  `);

  // Notify owner
  const ownerEmail = process.env.OWNER_EMAIL;
  if (ownerEmail && ownerEmail !== email) {
    const ip = req.headers['x-forwarded-for'] || req.ip || 'unknown';
    await sendEmail(ownerEmail, `Magic link requested: ${email}`, `
      <p><strong>${email}</strong> requested a magic link at ${new Date().toISOString()} from IP ${ip}</p>
    `);
  }

  console.log(`[MAGIC_LINK] ${email} at ${new Date().toISOString()}`);
  res.json({ ok: true });
});

// Verify token → create session
app.get('/auth', async (req, res) => {
  const entry = pendingTokens.get(req.query.token);

  if (!entry || Date.now() > entry.expires) {
    return res.redirect('/?error=expired');
  }

  pendingTokens.delete(req.query.token); // single use

  const sessionId = crypto.randomBytes(32).toString('hex');
  sessions.set(sessionId, {
    email: entry.email,
    expires: Date.now() + 7 * 24 * 60 * 60 * 1000,
    createdAt: new Date().toISOString(),
  });

  const ip     = req.headers['x-forwarded-for'] || req.ip || 'unknown';
  const record = { email: entry.email, time: new Date().toISOString(), ip };
  loginLog.push(record);
  console.log(`[LOGIN] ${record.email} from ${record.ip} at ${record.time}`);

  // Notify owner of successful login
  const ownerEmail = process.env.OWNER_EMAIL;
  if (ownerEmail && ownerEmail !== entry.email) {
    await sendEmail(ownerEmail, `Login: ${entry.email}`, `
      <p><strong>${entry.email}</strong> logged in at ${record.time} from IP ${record.ip}</p>
    `);
  }

  const isSecure = req.secure || req.headers['x-forwarded-proto'] === 'https';
  res.cookie('session', sessionId, {
    httpOnly: true,
    secure: isSecure,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  res.redirect('/app');
});

// Protected app
app.get('/app', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'app.html'));
});

// Current user info (for the app to display)
app.get('/api/me', requireAuth, (req, res) => {
  res.json({ email: req.userEmail });
});

// Logout
app.get('/logout', (req, res) => {
  const sessionId = req.cookies?.session;
  if (sessionId) sessions.delete(sessionId);
  res.clearCookie('session');
  res.redirect('/');
});

// Admin: login log
app.get('/admin', (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (adminKey && req.query.key !== adminKey) {
    return res.status(403).send('Forbidden — add ?key=YOUR_ADMIN_KEY to the URL');
  }

  const rows = [...loginLog].reverse().map(r =>
    `<tr><td>${r.email}</td><td>${r.time}</td><td>${r.ip}</td></tr>`
  ).join('');

  const uniqueEmails = [...new Set(loginLog.map(r => r.email))];

  res.send(`<!DOCTYPE html>
<html><head><title>Login Log</title>
<style>
  body { font-family: -apple-system, sans-serif; padding: 32px; max-width: 800px; margin: 0 auto; background: #f3f4f6; }
  .card { background: white; border-radius: 12px; border: 1px solid #e5e7eb; padding: 24px; margin-bottom: 16px; }
  h1 { font-size: 20px; font-weight: 700; color: #0a66c2; margin-bottom: 4px; }
  .meta { color: #6b7280; font-size: 13px; margin-bottom: 20px; }
  .emails { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  .email-tag { background: #eff6ff; color: #1d4ed8; border-radius: 999px; padding: 3px 10px; font-size: 12px; font-weight: 500; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #f3f4f6; }
  th { background: #f9fafb; font-weight: 600; color: #374151; }
  td { color: #6b7280; }
  td:first-child { color: #111827; font-weight: 500; }
</style>
</head><body>
<div class="card">
  <h1>Login Log</h1>
  <div class="meta">${loginLog.length} total logins · ${uniqueEmails.length} unique users</div>
  <div class="emails">${uniqueEmails.map(e => `<span class="email-tag">${e}</span>`).join('') || '<span style="color:#9ca3af;font-size:13px">No logins yet</span>'}</div>
  <table>
    <thead><tr><th>Email</th><th>Time</th><th>IP</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="3" style="color:#9ca3af">No logins yet</td></tr>'}</tbody>
  </table>
</div>
</body></html>`);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
