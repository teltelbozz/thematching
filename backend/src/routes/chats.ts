import { Router } from 'express';
import type { Pool } from 'pg';
const router = Router();

router.get('/:roomId/messages', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { roomId } = req.params;
  const { rows } = await db.query(`SELECT id, user_id, body, created_at FROM messages WHERE room_id = $1 ORDER BY id DESC LIMIT 50`, [roomId]);
  res.json(rows);
});

router.post('/:roomId/messages', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { roomId } = req.params;
  const userId = 1; // TODO: from auth
  const { body } = req.body;
  const { rows } = await db.query(`INSERT INTO messages (room_id, user_id, body) VALUES ($1,$2,$3) RETURNING *`, [roomId, userId, body]);
  res.status(201).json(rows[0]);
});

export default router;