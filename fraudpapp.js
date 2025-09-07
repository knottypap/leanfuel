/**
 * fraud-protect-app.js
 * Minimal layered fraud protection example (Express)
 *
 * Features:
 * - Rate limiter with Redis fallback
 * - Simple device/IP fingerprint
 * - Risk scoring engine (rules)
 * - Challenge escalation: allow / require captcha or 2FA or block
 * - Event logging and webhook alert
 */

const express = require('express');
const rateLimit = require('express-rate-limit');
const RedisStore = require('rate-limit-redis');
const redis = require('redis');
const geoip = require('geoip-lite');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // for alert webhook
const helmet = require('helmet');
const cookieParser = require('cookie-parser');

const PORT = process.env.PORT || 3000;
const REDIS_URL = process.env.REDIS_URL || null; // set to redis://... to enable
const ALERT_WEBHOOK = process.env.ALERT_WEBHOOK || null; // optional webhook for high-risk events

// Basic in-memory store for fingerprint history (demo only) - replace with DB in prod
const userHistoryStore = new Map(); // key = userId (or email), value = { ips: Set, devices: Set, timestamps: [] }
const globalIPBlacklist = new Set(['203.0.113.45']); // example blacklisted IP
const emailDomainBlacklist = new Set(['fraudmail.com']);

// Create Redis client if URL provided
let redisClient = null;
if (REDIS_URL) {
  redisClient = redis.createClient({ url: REDIS_URL });
  redisClient.connect().catch(err => {
    console.error('Redis connect failed:', err);
    redisClient = null;
  });
}

// Rate limiter config (login endpoint example)
const createRateLimiter = (max, windowMs) => {
  if (redisClient) {
    return rateLimit({
      windowMs,
      max,
      standardHeaders: true,
      legacyHeaders: false,
      store: new RedisStore({
        sendCommand: (...args) => redisClient.sendCommand(args),
      }),
      keyGenerator: (req) => {
        // Use IP + user identifier (if present) to avoid attackers rotating IPs
        return req.ip + '::' + (req.body?.email || req.query?.email || 'anon');
      },
    });
  } else {
    // fallback memory limiter
    return rateLimit({
      windowMs,
      max,
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => req.ip + '::' + (req.body?.email || req.query?.email || 'anon'),
    });
  }
};

// Basic fingerprint extraction
function makeFingerprint(req) {
  // Combine elements that are common and accessible server-side
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const acceptLang = req.headers['accept-language'] || '';
  const forwarded = req.headers['x-forwarded-for'] || '';
  const flash = req.headers['user-agent-platform'] || ''; // placeholder

  // Simple hash (not cryptographic here)
  const raw = [ua, ip, acceptLang, forwarded, flash].join('|');
  const hash = require('crypto').createHash('sha256').update(raw).digest('hex');
  return { hash, ua, ip, acceptLang, forwarded };
}

// Rule-based risk scoring function
function scoreRisk({ userId, email, ip, fingerprintHash, ua, payload }) {
  let score = 0;
  const reasons = [];

  // 1) IP blacklists
  if (globalIPBlacklist.has(ip)) {
    score += 50; reasons.push('ip_blacklist');
  }

  // 2) Email domain blacklist
  const domain = (email || '').split('@')[1]?.toLowerCase();
  if (domain && emailDomainBlacklist.has(domain)) {
    score += 40; reasons.push('email_domain_blacklist');
  }

  // 3) Geo mismatch: check geoip country vs claimed country (if provided)
  const geo = geoip.lookup(ip);
  const country = geo?.country || '??';
  if (payload?.declared_country && payload.declared_country !== country) {
    score += 20; reasons.push(`country_mismatch server:${country} declared:${payload.declared_country}`);
  }

  // 4) Velocity - many attempts from same userId or IP in short time
  const history = userHistoryStore.get(userId) || { ips: new Set(), devices: new Set(), timestamps: [] };
  const now = Date.now();
  const recentTimestamps = history.timestamps.filter(t => now - t < 10 * 60 * 1000); // 10min window
  if (recentTimestamps.length > 5) { score += 25; reasons.push('high_velocity'); }

  // 5) Device/IP churn - many different IPs/devices for the same user
  if (history.ips && history.ips.size > 3) { score += 15; reasons.push('ip_churn'); }
  if (history.devices && history.devices.size > 3) { score += 15; reasons.push('device_churn'); }

  // 6) Known risky UA patterns (simple heuristics)
  if (ua && /curl|wget|scrapy|bot|python-requests/i.test(ua)) {
    score += 10; reasons.push('suspicious_user_agent');
  }

  // 7) New account + high transaction amount
  if (payload?.account_age_days !== undefined && payload.account_age_days < 2 && payload?.amount && payload.amount > 200) {
    score += 30; reasons.push('new_account_large_amount');
  }

  // 8) Fingerprint mismatch with previous known device for same user
  if (history.devices && history.devices.size > 0 && !history.devices.has(fingerprintHash)) {
    score += 10; reasons.push('new_device_for_user');
  }

  // Normalize score
  if (score > 100) score = 100;

  return { score, reasons, country };
}

// Action decision based on risk score
function decideAction(risk) {
  // risk.score is 0..100
  if (risk.score >= 80) return { action: 'block', reason: 'high_risk' };
  if (risk.score >= 50) return { action: 'challenge', reason: 'require_2fa_or_captcha' };
  if (risk.score >= 30) return { action: 'step_up', reason: 'require_additional_verification' };
  return { action: 'allow', reason: 'low_risk' };
}

// Simple logging + optional webhook for high-risk
async function logEvent(type, details) {
  const entry = { ts: new Date().toISOString(), type, details };
  console.log('FRAUD_EVENT', JSON.stringify(entry));
  try {
    if (ALERT_WEBHOOK && details && details.risk && details.risk.score >= 50) {
      await fetch(ALERT_WEBHOOK, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(entry),
      });
    }
  } catch (err) {
    console.warn('failed to send alert webhook', err);
  }
}

// Express app
const app = express();
app.use(helmet());
app.set('trust proxy', true); // if behind load balancer
app.use(bodyParser.json());
app.use(cookieParser());

// Rate limiter for login route: 10 attempts per 10 minutes per ip+email (customizable)
const loginLimiter = createRateLimiter(10, 10 * 60 * 1000);
const transactionLimiter = createRateLimiter(20, 60 * 60 * 1000); // example for transaction endpoint

// Example /login endpoint
app.post('/login', loginLimiter, async (req, res) => {
  const { email } = req.body;
  const userId = (email || '').toLowerCase();
  const fp = makeFingerprint(req);
  const payload = {
    declared_country: req.body.declared_country,
    account_age_days: req.body.account_age_days,
  };

  // Score risk
  const risk = scoreRisk({
    userId,
    email,
    ip: fp.ip,
    fingerprintHash: fp.hash,
    ua: fp.ua,
    payload,
  });

  const decision = decideAction(risk);

  await logEvent('login_attempt', { userId, email, ip: fp.ip, fingerprint: fp.hash, risk, decision });

  // Update history store
  const hist = userHistoryStore.get(userId) || { ips: new Set(), devices: new Set(), timestamps: [] };
  hist.ips.add(fp.ip);
  hist.devices.add(fp.hash);
  hist.timestamps.push(Date.now());
  // Keep last 100 timestamps
  if (hist.timestamps.length > 100) hist.timestamps = hist.timestamps.slice(-100);
  userHistoryStore.set(userId, hist);

  // Respond based on decision
  if (decision.action === 'block') {
    return res.status(403).json({ status: 'blocked', reason: decision.reason });
  }
  if (decision.action === 'challenge') {
    // Return that frontend must show CAPTCHA or require 2FA
    return res.status(200).json({ status: 'challenge', challenge: '2fa_or_captcha', reason: decision.reason });
  }
  // Otherwise proceed with normal login flow (authenticate here)
  // NOTE: actual authentication (password check, bcrypt, etc) should happen AFTER or before scoring depending on design.
  return res.status(200).json({ status: 'ok', risk: risk.score, reason: 'proceed_with_auth' });
});

// Example /transaction endpoint (higher-security)
app.post('/transaction', transactionLimiter, async (req, res) => {
  // Expect payload: { userId, amount, account_age_days, declared_country, email }
  const { userId, amount, account_age_days, declared_country, email } = req.body;
  if (!userId) return res.status(400).json({ error: 'missing userId' });

  const fp = makeFingerprint(req);
  const risk = scoreRisk({
    userId,
    email,
    ip: fp.ip,
    fingerprintHash: fp.hash,
    ua: fp.ua,
    payload: { account_age_days, amount, declared_country },
  });
  const decision = decideAction(risk);
  await logEvent('transaction_attempt', { userId, amount, ip: fp.ip, risk, decision });

  // Implement step-up behavior
  if (decision.action === 'block') {
    return res.status(403).json({ status: 'blocked', reason: decision.reason });
  }
  if (decision.action === 'challenge' || decision.action === 'step_up') {
    // e.g., require 2FA code, or delay transaction until review
    return res.status(200).json({ status: 'challenge', required: ['2fa', 'manual_review'], risk: risk.score });
  }

  // If allowed: perform transaction (placeholder)
  // TODO: plug actual payment/transfer API and guard with two-party auth
  return res.status(200).json({ status: 'approved', risk: risk.score });
});

// Admin endpoint to fetch user history (demo only)
app.get('/admin/history/:userId', (req, res) => {
  const hist = userHistoryStore.get(req.params.userId) || { ips: [], devices: [], timestamps: [] };
  res.json({
    ips: Array.from(hist.ips || []),
    devices: Array.from(hist.devices || []),
    recentAttempts: hist.timestamps || [],
  });
});

// Basic health
app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Fraud protection demo running on port ${PORT}`);
  if (!redisClient) console.log('Redis not configured — using in-memory rate limiting fallback');
});
