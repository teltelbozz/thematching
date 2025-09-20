import type { Request, Response, NextFunction } from 'express';
import type { Pool } from 'pg';

export default async function devAuth(req: Request, res: Response, next: NextFunction) {
  if (process.env.VERCEL_ENV === 'production') return next();
  if (process.env.DEV_FAKE_AUTH !== '1') return next();

  const expectKey = process.env.DEV_FAKE_AUTH_KEY;
  if (expectKey && req.header('x-dev-auth-key') !== expectKey) {
    return res.status(401).json({ error: 'dev_auth_denied' });
  }

  const db = req.app.locals.db as Pool;
  const lineUserId = req.header('x-dev-line-user-id') || process.env.DEV_FAKE_LINE_USER_ID || 'dev:local';
  const email = process.env.DEV_FAKE_EMAIL || 'dev@local.test';

  const sql = `WITH ins AS (
    INSERT INTO users (line_user_id, email)
    VALUES ($1, $2)
    ON CONFLICT (line_user_id) DO NOTHING
    RETURNING id
  )
  SELECT id FROM ins
  UNION ALL
  SELECT id FROM users WHERE line_user_id = $1
  LIMIT 1`;
  const { rows } = await db.query(sql, [lineUserId, email]);
  (req as any).userId = rows[0].id;
  next();
}
