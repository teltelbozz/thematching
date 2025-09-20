import { Router } from 'express';
import type { Pool } from 'pg';
const router = Router();

router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { slot_id } = req.body;
  const { rows } = await db.query(`INSERT INTO matches (slot_id, status, confirmed_at) VALUES ($1, 'confirmed', NOW()) RETURNING *`, [slot_id]);
  const matchId = rows[0].id;
  const room = await db.query(`INSERT INTO chat_rooms (match_id) VALUES ($1) RETURNING *`, [matchId]);
  res.status(201).json({ match: rows[0], room: room.rows[0] });
});

export default router;