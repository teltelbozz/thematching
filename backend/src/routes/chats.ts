import { Router } from 'express';
import type { Pool } from 'pg';

const router = Router();

// GET /chats/:roomId/messages
router.get('/:roomId/messages', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const roomId = Number(req.params.roomId);

  const r = await db.query(
    `SELECT id, user_id, body, created_at
     FROM chat_messages
     WHERE room_id = $1
     ORDER BY created_at ASC`,
    [roomId]
  );

  return res.json(r.rows);
});

// POST /chats/:roomId/messages
router.post('/:roomId/messages', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const roomId = Number(req.params.roomId);
  const userId = (req as any).userId || 1; // devAuth で付与される
  const { body } = req.body;

  const r = await db.query(
    `INSERT INTO chat_messages (room_id, user_id, body)
     VALUES ($1, $2, $3)
     RETURNING *`,
    [roomId, userId, body]
  );

  return res.json(r.rows[0]);
});

export default router;