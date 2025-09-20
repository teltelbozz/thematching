import { Router } from 'express';
import type { Pool } from 'pg';
const router = Router();

router.get('/', (_req, res) => res.json({ ok: true }));

router.get('/db', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const r = await db.query('SELECT NOW() AS now');
  res.json({ now: r.rows[0].now });
});

export default router;