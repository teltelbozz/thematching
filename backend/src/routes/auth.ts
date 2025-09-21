import { Router } from 'express';
import type { Pool } from 'pg';
import { createRemoteJWKSet, jwtVerify, SignJWT } from 'jose';

const router = Router();

// ----- 設定 -----
const LINE_JWKS = createRemoteJWKSet(new URL('https://api.line.me/oauth2/v2.1/certs'));
const LINE_ISSUER = process.env.LINE_ISSUER || 'https://access.line.me';
const LINE_CHANNEL_ID = process.env.LINE_CHANNEL_ID!;
const SESSION_SECRET = new TextEncoder().encode(process.env.SESSION_SECRET || 'dev-secret');
const SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME || 'sid';
const SESSION_TTL_SECONDS = Number(process.env.SESSION_TTL_SECONDS || 60 * 60 * 24 * 7); // 7日

// ----- ユーティリティ -----
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

// ----- POST /auth/login -----
// Body: { id_token: string }
router.post('/login', async (req, res) => {
  try {
    const { id_token } = req.body || {};
    if (!id_token) return res.status(400).json({ error: 'missing_id_token' });

    // デバッグ: 受け取ったトークンのexp/iat/nowを確認
    const parts = String(id_token).split('.');
    if (parts.length === 3) {
      try {
        const payloadStr = Buffer.from(parts[1], 'base64url').toString('utf8');
        const payload = JSON.parse(payloadStr);
        const now = Math.floor(Date.now()/1000);
        console.log('[auth/login dbg]', { exp: payload?.exp, iat: payload?.iat, now });
      } catch {}
    }

    const { payload } = await jwtVerify(id_token, LINE_JWKS, {
      issuer: LINE_ISSUER,
      audience: LINE_CHANNEL_ID,
      clockTolerance: 900, // ← まずは15分（動作確認後は300(5分)へ）
    });

    // 2) ユーザー情報（LINEのクレーム）
    const lineUserId = String(payload.sub); // 一意
    const displayName = (payload as any).name || 'LINE User';
    const picture = (payload as any).picture || null;

    const db = req.app.locals.db as Pool;

    // 3) users Upsert（line_user_id 基準）
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

    // 4) user_profiles Upsert（表示名/写真を初期投入 or 更新）
    const profSql = `
      INSERT INTO user_profiles (user_id, nickname, photo_url)
      VALUES ($1, $2, $3)
      ON CONFLICT (user_id)
      DO UPDATE SET nickname = COALESCE(EXCLUDED.nickname, user_profiles.nickname),
                    photo_url = COALESCE(EXCLUDED.photo_url, user_profiles.photo_url),
                    updated_at = NOW()
      RETURNING user_id, nickname, photo_url
    `;
    const p = await db.query(profSql, [userId, displayName, picture]);

    // 5) セッションJWTを発行し Cookie に保存（クロスサイト対応）
    const token = await signSession(userId);
    res.setHeader('Set-Cookie', [
      // frontend と backend が異なるドメインのため SameSite=None; Secure が必須
      `${SESSION_COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${SESSION_TTL_SECONDS}`,
    ]);

    return res.status(200).json({
      ok: true,
      user: { id: userId, line_user_id: lineUserId },
      profile: p.rows[0],
      // デバッグ時に役立つ付加情報（本番では外してOK）
      _dbg: {
        alg: protectedHeader?.alg,
        iss: payload?.iss,
        aud: payload?.aud,
        exp: payload?.exp,
        iat: payload?.iat,
      },
    });
  } catch (e: any) {
    // ← ここが「エラー詳細を増やす」追加点
    console.error(
      '[auth/login failed]',
      e?.code || '',
      e?.name || '',
      e?.message || e
    );
    return res.status(401).json({ error: 'invalid_id_token' });
  }
});

// ----- GET /auth/me -----
// Cookie のセッション or Authorization: Bearer で判定
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