import { Router } from 'express';
import type { Pool } from 'pg';
import { createRemoteJWKSet, jwtVerify, SignJWT, JWTPayload } from 'jose';

const router = Router();

// ===== Settings =====
const LINE_JWKS = createRemoteJWKSet(new URL('https://api.line.me/oauth2/v2.1/certs'));
const LINE_ISSUER = process.env.LINE_ISSUER || 'https://access.line.me';
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID!;
const DEBUG_AUTH = process.env.DEBUG_AUTH === '1';

const ACCESS_TTL_SEC = Number(process.env.ACCESS_TTL_SECONDS || 60 * 10);      // 10分
const REFRESH_TTL_SEC = Number(process.env.REFRESH_TTL_SECONDS || 60 * 60 * 7); // 7時間(例)
const ACCESS_SECRET = new TextEncoder().encode(process.env.ACCESS_SECRET || 'dev-access');
const REFRESH_SECRET = new TextEncoder().encode(process.env.REFRESH_SECRET || 'dev-refresh');

const REFRESH_COOKIE = process.env.REFRESH_COOKIE_NAME || 'rt';
const COOKIE_BASE = `Path=/; HttpOnly; Secure; SameSite=None`; // 別ドメイン運用前提

// ===== utils =====
type AccessClaims = JWTPayload & { uid: number };
type RefreshClaims = JWTPayload & { uid: number, rot?: number }; // rot: rotation counter (シンプル例)

async function signAccess(uid: number) {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ uid } as AccessClaims)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TTL_SEC)
    .sign(ACCESS_SECRET);
}

async function signRefresh(uid: number, rot = 0) {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ uid, rot } as RefreshClaims)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + REFRESH_TTL_SEC)
    .sign(REFRESH_SECRET);
}

function readBearer(req: any): string | undefined {
  const b = String(req.headers['authorization'] || '');
  return b.startsWith('Bearer ') ? b.slice(7) : undefined;
}

function readCookie(req: any, name: string): string | undefined {
  const raw = req.headers?.cookie;
  if (!raw) return;
  const target = raw.split(';').map((s: string) => s.trim()).find((s: string) => s.startsWith(name + '='));
  return target ? decodeURIComponent(target.split('=')[1]) : undefined;
}

// ===== /auth/login =====
// Body: { id_token: string } (LIFF の ID トークン)
router.post('/login', async (req, res) => {
  try {
    const { id_token } = req.body || {};
    if (!id_token) return res.status(400).json({ error: 'missing_id_token' });

    if (DEBUG_AUTH) {
      try {
        const [h64, p64] = String(id_token).split('.');
        const headerStr = Buffer.from(h64, 'base64url').toString('utf8');
        const payloadStr = Buffer.from(p64, 'base64url').toString('utf8');
        const headerObj = JSON.parse(headerStr);
        const payloadObj = JSON.parse(payloadStr);
        const now = Math.floor(Date.now() / 1000);
        console.log('[auth/login expect]', { issuer: LINE_ISSUER, audience: LINE_CHANNEL_ID });
        console.log('[auth/login incoming]', {
          alg: headerObj?.alg, iss: payloadObj?.iss, aud: payloadObj?.aud,
          sub: payloadObj?.sub, iat: payloadObj?.iat, exp: payloadObj?.exp,
          now, exp_minus_now: (payloadObj?.exp ?? 0) - now,
        });
      } catch {}
    }

    const { payload } = await jwtVerify(id_token, LINE_JWKS, {
      issuer: LINE_ISSUER,
      audience: LINE_CHANNEL_ID,
      clockTolerance: 300, // 5分
    });

    // Create/Update user (line_user_id 基準)
    const db = req.app.locals.db as Pool;
    const lineUserId = String(payload.sub);
    const displayName = (payload as any).name || 'LINE User';
    const picture = (payload as any).picture || null;

    const userSql = `
      WITH ins AS (
        INSERT INTO users (line_user_id, email)
        VALUES ($1, NULL)
        ON CONFLICT (line_user_id) DO NOTHING
        RETURNING id
      )
      SELECT id FROM ins
      UNION ALL
      SELECT id FROM users WHERE line_user_id = $1
      LIMIT 1
    `;
    const u = await db.query(userSql, [lineUserId]);
    const userId: number = u.rows[0].id;

    const profSql = `
      INSERT INTO user_profiles (user_id, nickname, photo_url)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id) DO UPDATE
        SET nickname = COALESCE(EXCLUDED.nickname, user_profiles.nickname),
            photo_url = COALESCE(EXCLUDED.photo_url, user_profiles.photo_url),
            updated_at = NOW()
      RETURNING user_id, nickname, photo_url
    `;
    const p = await db.query(profSql, [userId, displayName, picture]);

    // === Issue tokens
    const access = await signAccess(userId);
    const refresh = await signRefresh(userId, 0);

    // HttpOnly Refresh Cookie (クロスサイト運用)
    res.setHeader('Set-Cookie', [
      `${REFRESH_COOKIE}=${encodeURIComponent(refresh)}; ${COOKIE_BASE}; Max-Age=${REFRESH_TTL_SEC}`,
    ]);

    return res.status(200).json({
      ok: true,
      access_token: access,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SEC,
      user: { id: userId, line_user_id: lineUserId },
      profile: p.rows[0],
    });
  } catch (e: any) {
    console.error('[auth/login failed]', e?.code || '', e?.name || '', e?.message || e);
    return res.status(401).json({ error: 'invalid_id_token' });
  }
});

// ===== /auth/refresh =====
// Cookie の Refresh から新しい Access を返す（JSON）
router.post('/refresh', async (req, res) => {
  try {
    const rt = readCookie(req, REFRESH_COOKIE);
    if (!rt) return res.status(401).json({ error: 'no_refresh_token' });

    const { payload } = await jwtVerify(rt, REFRESH_SECRET, { algorithms: ['HS256'], clockTolerance: 300 });
    const uid = (payload as RefreshClaims).uid;
    if (typeof uid !== 'number') return res.status(401).json({ error: 'invalid_refresh' });

    // （必要ならここで DB 側のリフレッシュ状態チェック/回転検知）

    const access = await signAccess(uid);
    return res.json({
      ok: true,
      access_token: access,
      token_type: 'Bearer',
      expires_in: ACCESS_TTL_SEC,
    });
  } catch (e: any) {
    console.error('[auth/refresh failed]', e?.code || '', e?.name || '', e?.message || e);
    return res.status(401).json({ error: 'refresh_failed' });
  }
});

// ===== /auth/logout =====
// Refresh を失効（簡易版：Cookie を消す）
router.post('/logout', async (req, res) => {
  res.setHeader('Set-Cookie', [
    `${REFRESH_COOKIE}=; ${COOKIE_BASE}; Max-Age=0`,
  ]);
  return res.json({ ok: true });
});

// ===== /auth/me =====
// Bearer アクセストークンでユーザー情報を返す
router.get('/me', async (req, res) => {
  try {
    const token = readBearer(req);
    if (!token) {
      console.warn('[auth/me] no Authorization header');
      return res.status(401).json({ error: 'unauthenticated' });
    }
    const { payload } = await jwtVerify(token, ACCESS_SECRET, { algorithms: ['HS256'], clockTolerance: 60 });
    const uid = (payload as AccessClaims).uid;
    if (typeof uid !== 'number') {
      console.warn('[auth/me] invalid uid in access token');
      return res.status(401).json({ error: 'unauthenticated' });
    }

    // ここに来ていれば GET は実際に到達している
    console.log('[auth/me] uid=', uid);

    const db = req.app.locals.db as Pool;
    const r = await db.query(`
      SELECT u.id, u.line_user_id,
             p.nickname, p.age, p.gender, p.occupation, p.photo_url, p.photo_masked_url, p.verified_age
      FROM users u
      LEFT JOIN user_profiles p ON p.user_id = u.id
      WHERE u.id = $1
    `, [uid]);

    if (!r.rows[0]) return res.status(404).json({ error: 'not_found' });
    return res.json({ user: r.rows[0] });
  } catch (e:any) {
    console.warn('[auth/me] verify failed:', e?.code || '', e?.message || e);
    return res.status(401).json({ error: 'unauthenticated' });
  }
});

export default router;