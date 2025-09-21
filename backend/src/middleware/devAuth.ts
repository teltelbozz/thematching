import type { Request, Response, NextFunction } from 'express';
import type { Pool } from 'pg';

/**
 * 開発用の擬似認証ミドルウェア
 * - ENV: DEV_FAKE_AUTH=1 で有効
 * - 任意の固定ユーザーを upsert し、req.userId に設定
 * - DB未初期化時は「フェイルオープン」で next()（サーバを落とさない）
 * - 期待キー（DEV_FAKE_AUTH_KEY）を設定している場合はヘッダ一致でのみ許可
 *   - ヘッダ名: x-dev-auth-key
 */
export default async function devAuth(req: Request, res: Response, next: NextFunction) {
  try {
    // OFF なら何もしない
    if (process.env.DEV_FAKE_AUTH !== '1') return next();

    // 期待キーが指定されているならチェック（キー不一致は 401 で拒否）
    const expectKey = process.env.DEV_FAKE_AUTH_KEY;
    if (expectKey && req.header('x-dev-auth-key') !== expectKey) {
      return res.status(401).json({ error: 'dev_auth_denied' });
    }

    // DB 取得（未初期化なら素通り：落とさない）
    const db = req.app?.locals?.db as Pool | undefined;
    if (!db) {
      console.warn('[devAuth] db is not ready; skipping (pass-through)');
      return next();
    }

    // ダミーID/メール（ヘッダ優先）
    const lineUserId = req.header('x-dev-line-user-id') || process.env.DEV_FAKE_LINE_USER_ID || 'dev:local';
    const email = process.env.DEV_FAKE_EMAIL || 'dev@local.test';

    // users に upsert → id を取得
    const sql = `
      WITH ins AS (
        INSERT INTO users (line_user_id, email)
        VALUES ($1, $2)
        ON CONFLICT (line_user_id) DO NOTHING
        RETURNING id
      )
      SELECT id FROM ins
      UNION ALL
      SELECT id FROM users WHERE line_user_id = $1
      LIMIT 1
    `;
    const { rows } = await db.query(sql, [lineUserId, email]);
    if (!rows[0]?.id) {
      console.warn('[devAuth] upsert returned no id; skipping');
      return next();
    }

    (req as any).userId = rows[0].id;
    return next();
  } catch (e: any) {
    console.error('[devAuth] error:', e?.message || e);
    // 失敗しても開発専用なので落とさず通す
    return next();
  }
}