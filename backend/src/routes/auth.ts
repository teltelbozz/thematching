import { Router } from 'express';
import type { Pool } from 'pg';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';

const router = Router();

// ===== Settings =====
const LINE_JWKS = createRemoteJWKSet(new URL('https://api.line.me/oauth2/v2.1/certs'));
const LINE_ISSUER = process.env.LINE_ISSUER || 'https://access.line.me';
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID!;
const SESSION_SECRET = new TextEncoder().encode(process.env.SESSION_SECRET || 'dev-secret');
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'sid';
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 60 * 60 * 24 * 7); // 7d
const DEBUG_AUTH = process.env.DEBUG_AUTH === '1'; // ← DEBUG 時だけ詳細ログを出す

// ===== Utils =====
async function signSession(uid: number) {
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ uid })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(now + SESSION_TTL_SECONDS)
    .sign(SESSION_SECRET);
}

function readCookie(req: any, name: string): string | undefined {
  const raw = req.headers?.cookie;
  if (!raw) return;
  const target = raw
    .split(';')
    .map((s: string) => s.trim())
    .find((s: string) => s.startsWith(name + '='));
  return target ? decodeURIComponent(target.split('=')[1]) : undefined;
}

export async function verifySession(token?: string): Promise<number | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, SESSION_SECRET, { algorithms: ['HS256'] });
    const uid = (payload as any).uid;
    return typeof uid === 'number' ? uid : null;
  } catch {
    return null;
  }
}

// ===== POST /auth/login =====
// Body: { id_token: string }
router.post('/login', async (req, res) => {
  try {
    const { id_token } = req.body || {};
    if (!id_token) return res.status(400).json({ error: 'missing_id_token' });

    // --- DEBUG: verify 前にペイロードの中身だけ覗く（署名はまだ検証しない） ---
    if (DEBUG_AUTH) {
      try {
        const [h64, p64] = String(id_token).split('.');
        const headerStr = Buffer.from(h64, 'base64url').toString('utf8');
        const payloadStr = Buffer.from(p64, 'base64url').toString('utf8');
        const headerObj = JSON.parse(headerStr);
        const payloadObj = JSON.parse(payloadStr);
        const now = Math.floor(Date.now() / 1000);

        console.log('[auth/login expect]', { issuer: LINE_ISSUER, audience: LINE_CHANNEL_ID });
        console.log('[auth/login dbg:incoming]', {
          alg: headerObj?.alg,
          iss: payloadObj?.iss,
          aud: payloadObj?.aud,
          sub: payloadObj?.sub,
          iat: payloadObj?.iat,
          exp: payloadObj?.exp,
          now,
          exp_minus_now: (payloadObj?.exp ?? 0) - now,
        });
      } catch (e) {
        console.warn('[auth/login dbg] failed to decode incoming token payload');
      }
    }
    // -----------------------------------------------------------------------

    // 1) LINE id_token の署名・クレーム検証（時刻ズレを許容）
    const { payload, protectedHeader } = await jwtVerify(id_token, LINE_JWKS, {
      issuer: LINE_ISSUER,
      audience: LINE_CHANNEL_ID, // ← LINE Login のチャネルIDと一致必須
      clockTolerance: 300,       // 5分の時計ズレ許容（必要に応じて 900 に一時拡大可）
    });

    if (DEBUG_AUTH) {
      console.log('[auth/login dbg:verified]', {
        alg: protectedHeader?.alg,
        iss: payload?.iss,
        aud: payload?.aud,
        sub: payload?.sub,
        iat: payload?.iat,
        exp: payload?.exp,
      });
    }

    // 2) ユーザー情報（LINE claims）
    const lineUserId = String(payload.sub); // 一意のID
    const displayName = (payload as any).name || 'LINE User';
    const picture = (payload as any).picture || null;

    // 3) DB upsert
    const db = req.app.locals.db as Pool;

    // users upsert（line_user_id 基準）
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

    // user_profiles upsert（表示名/写真）
    const profSql = `
      INSERT INTO user_profiles (user_id, nickname, photo_url)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET
        nickname = COALESCE(EXCLUDED.nickname, user_profiles.nickname),
        photo_url = COALESCE(EXCLUDED.photo_url, user_profiles.photo_url),
        updated_at = NOW()
      RETURNING user_id, nickname, photo_url
    `;
    const p = await db.query(profSql, [userId, displayName, picture]);

    // 4) アプリ用セッションを Cookie へ（クロスサイト対応）
    const sessionToken = await signSession(userId);
    res.setHeader('Set-Cookie', [
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(sessionToken)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${SESSION_TTL_SECONDS}`,
    ]);

    return res.status(200).json({
      ok: true,
      user: { id: userId, line_user_id: lineUserId },
      profile: p.rows[0],
    });
  } catch (e: any) {
    // 失敗理由を詳しく出す（Vercel Logs で確認）
    console.error('[auth/login failed]', e?.code || '', e?.name || '', e?.message || e);
    return res.status(401).json({ error: 'invalid_id_token' });
  }
});

// ===== GET /auth/me =====
// Cookie セッション or Authorization: Bearer
router.get('/me', async (req, res) => {
  const bearer = String(req.headers['authorization'] || '');
  const tokenFromBearer = bearer.startsWith('Bearer ') ? bearer.slice(7) : undefined;
  const token = tokenFromBearer || readCookie(req, SESSION_COOKIE_NAME);
  const uid = await verifySession(token);
  if (!uid) return res.status(401).json({ error: 'unauthenticated' });

  const db = req.app.locals.db as Pool;
  const sql = `
    SELECT u.id, u.line_user_id,
           p.nickname, p.age, p.gender, p.occupation, p.photo_url, p.photo_masked_url, p.verified_age
    FROM users u
    LEFT JOIN user_profiles p ON p.user_id = u.id
    WHERE u.id = $1
  `;
  const r = await db.query(sql, [uid]);
  if (!r.rows[0]) return res.status(404).json({ error: 'not_found' });
  return res.json({ user: r.rows[0] });
});

export default router;