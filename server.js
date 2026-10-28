import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual, createHash } from 'node:crypto';
import { promisify } from 'node:util';
import { readFile, writeFile, mkdir, rename } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(scryptCallback);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isVercel = Boolean(process.env.VERCEL);
const dataDir = isVercel ? path.join('/tmp', 'data') : path.join(__dirname, 'data');
const dbPath = path.join(dataDir, 'store.json');
const distDir = path.join(__dirname, 'dist');
const app = express();
const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT || 3001);
const COOKIE = 'fraudshield_session';
const SESSION_MS = 1000 * 60 * 60 * 8;

app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '20kb', strict: true }));
app.use((req, res, next) => {
  if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method) && req.headers.origin) {
    const host = req.get('host');
    const originHost = req.headers.origin.replace(/^https?:\/\//, '');
    if (originHost !== host) return res.status(403).json({ error: 'Request origin rejected.' });
  }
  next();
});
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many authentication attempts. Please wait 15 minutes and try again.' } });

let store = { users: [], sessions: [] };
let writeQueue = Promise.resolve();
async function loadStore() {
  await mkdir(dataDir, { recursive: true });
  try { store = JSON.parse(await readFile(dbPath, 'utf8')); }
  catch (e) { if (e.code !== 'ENOENT') throw e; await saveStore(); }
  if (!Array.isArray(store.users)) store.users = [];
  if (!Array.isArray(store.sessions)) store.sessions = [];
  const now = Date.now(); store.sessions = store.sessions.filter(s => s.expiresAt > now);
}
function saveStore() {
  writeQueue = writeQueue.then(async () => {
    await mkdir(dataDir, { recursive: true });
    const temp = `${dbPath}.tmp`;
    await writeFile(temp, JSON.stringify(store, null, 2), { mode: 0o600 });
    await rename(temp, dbPath);
  });
  return writeQueue;
}
const hashToken = token => createHash('sha256').update(token).digest('hex');
const normalizeEmail = email => String(email || '').trim().toLowerCase();
function validEmail(email) { return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email); }
async function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt.toString('base64')}$${Buffer.from(derived).toString('base64')}`;
}
async function verifyPassword(password, encoded) {
  try {
    const [algorithm, n, r, p, saltB64, hashB64] = encoded.split('$');
    if (algorithm !== 'scrypt') return false;
    const expected = Buffer.from(hashB64, 'base64');
    const actual = Buffer.from(await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024 }));
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch { return false; }
}
function publicUser(user) { return { id: user.id, name: user.name, email: user.email, role: user.role, createdAt: user.createdAt }; }
function setSessionCookie(res, token) {
  const flags = [`${COOKIE}=${token}`, 'HttpOnly', 'SameSite=Strict', 'Path=/', `Max-Age=${Math.floor(SESSION_MS / 1000)}`];
  if (isProduction) flags.push('Secure');
  res.setHeader('Set-Cookie', flags.join('; '));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${isProduction ? '; Secure' : ''}`);
}
async function requireAuth(req, res, next) {
  const cookie = String(req.headers.cookie || '').split(';').map(x => x.trim()).find(x => x.startsWith(`${COOKIE}=`));
  const token = cookie ? cookie.slice(COOKIE.length + 1) : '';
  if (!token) return res.status(401).json({ error: 'Please sign in to continue.' });
  const hashed = hashToken(token);
  const session = store.sessions.find(s => s.tokenHash === hashed && s.expiresAt > Date.now());
  if (!session) { clearSessionCookie(res); return res.status(401).json({ error: 'Your session expired. Please sign in again.' }); }
  const user = store.users.find(u => u.id === session.userId);
  if (!user) return res.status(401).json({ error: 'Account not found. Please sign in again.' });
  req.user = user; req.session = session; next();
}
app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'FraudShield API' }));
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'Name must contain 2–80 characters.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Password must be 10–128 characters long.' });
  if (store.users.some(u => u.email === email)) return res.status(409).json({ error: 'An account with this email already exists. Please sign in.' });
  const user = { id: randomBytes(16).toString('hex'), name, email, passwordHash: await hashPassword(password), role: 'analyst', createdAt: new Date().toISOString() };
  store.users.push(user);
  const token = randomBytes(32).toString('base64url');
  store.sessions.push({ tokenHash: hashToken(token), userId: user.id, expiresAt: Date.now() + SESSION_MS });
  await saveStore(); setSessionCookie(res, token);
  res.status(201).json({ user: publicUser(user) });
});
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = String(req.body?.password || '');
  if (!validEmail(email) || !password || password.length > 128) return res.status(400).json({ error: 'Enter a valid email and password.' });
  const user = store.users.find(u => u.email === email);
  // Keep failure response identical whether the email exists or not.
  if (!user || !(await verifyPassword(password, user.passwordHash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  const token = randomBytes(32).toString('base64url');
  store.sessions = store.sessions.filter(s => s.userId !== user.id && s.expiresAt > Date.now());
  store.sessions.push({ tokenHash: hashToken(token), userId: user.id, expiresAt: Date.now() + SESSION_MS });
  await saveStore(); setSessionCookie(res, token);
  res.json({ user: publicUser(user) });
});
app.get('/api/auth/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));
app.post('/api/auth/logout', requireAuth, async (req, res) => {
  store.sessions = store.sessions.filter(s => s.tokenHash !== req.session.tokenHash);
  await saveStore(); clearSessionCookie(res); res.json({ ok: true });
});
app.patch('/api/auth/profile', requireAuth, async (req, res) => {
  const name = String(req.body?.name || '').trim();
  const email = normalizeEmail(req.body?.email);
  if (name.length < 2 || name.length > 80) return res.status(400).json({ error: 'Name must contain 2–80 characters.' });
  if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
  if (store.users.some(u => u.email === email && u.id !== req.user.id)) return res.status(409).json({ error: 'That email is already used by another account.' });
  req.user.name = name; req.user.email = email; await saveStore(); res.json({ user: publicUser(req.user) });
});
app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError) return res.status(400).json({ error: 'Invalid JSON request.' });
  console.error('API error:', err.message); res.status(500).json({ error: 'Something went wrong. Please try again.' });
});

// Serve static frontend assets if built
app.use(express.static(distDir));
app.use((req, res, next) => {
  if (req.method !== 'GET' || req.path.startsWith('/api')) return next();
  res.sendFile(path.join(distDir, 'index.html'), err => {
    if (err) next();
  });
});

if (!isVercel) {
  await loadStore();
  app.listen(PORT, () => console.log(`FraudShield server listening on http://localhost:${PORT}`));
}

export { app, loadStore };
export default app;
