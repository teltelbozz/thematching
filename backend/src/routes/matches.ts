import { Router } from 'express';
import type { Pool } from 'pg';

const router = Router();

// POST /matches
router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { slot_id } = req.body;

  // 1. match を作成
  const m = await db.query(
    `INSERT INTO matches (slot_id, status, confirmed_at)
     VALUES ($1, 'confirmed', NOW())
     RETURNING *`,
    [slot_id]
  );

  // 2. chat room を作成
  const r = await db.query(
    `INSERT INTO chat_rooms (match_id)
     VALUES ($1)
     RETURNING *`,
    [m.rows[0].id]
  );

  return res.json({ match: m.rows[0], room: r.rows[0] });
});

export default router;