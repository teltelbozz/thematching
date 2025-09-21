// backend/src/index.ts
// 役割：DB(Pool) を初期化して app.locals.db にセット → 環境に応じて export or listen
// ESM 実行前提（package.json の "type":"module"）。import の拡張子に .js を付けること。

import { Pool } from 'pg';
import app from './app.js';

// ---- DB 初期化 -------------------------------------------------------------

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  console.warn('[boot] DATABASE_URL is not set. API routes using DB may fail.');
}

/**
 * Neon(Postgres) を想定。
 * - Vercel/Neon は SSL 必須なので rejectUnauthorized: false を付与（Neon側のCAで検証済み）
 * - 他のPostgresなら ssl オプションは環境に合わせて変更
 */
const pool = new Pool({
  connectionString: databaseUrl,
  ssl: databaseUrl ? { rejectUnauthorized: false } : undefined,
});

// ★ 最重要：devAuth を通る前に db を差し込む
app.locals.db = pool;

// ---- エクスポート / ローカル起動 -------------------------------------------

/**
 * Vercel(Serverless)では「デフォルトエクスポートされた Express アプリ」が実行対象。
 * そのため listen() は不要。export default だけ行う。
 */
export default app;

/**
 * ローカル開発で `node dist/index.js` や `ts-node src/index.ts` を直接叩く場合は
 * PORT が与えられている時だけ listen する。
 * （Vercel 実行時は PORT は不要＆与えない）
 */
const maybePort = process.env.PORT;
if (maybePort && process.env.NODE_ENV !== 'production') {
  const port = Number(maybePort) || 3000;
  app.listen(port, () => {
    console.log(`[boot] server started on http://localhost:${port}`);
  });
}

// ---- 終了時ハンドリング（任意。接続のクリーンアップ） -----------------------

function gracefulShutdown() {
  // Serverless では自動で破棄されるが、ローカル常駐プロセスでは明示的に閉じる
  pool.end().catch((e) => console.warn('[boot] pool.end() error:', e?.message || e));
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);