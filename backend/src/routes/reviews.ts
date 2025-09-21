import { Router } from 'express';
import type { Pool } from 'pg';

const router = Router();

// POST /reviews
router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const userId = (req as any).userId || 1; // devAuth
  const { match_id, rating, comment } = req.body;

  const r = await db.query(
    `INSERT INTO reviews (match_id, user_id, rating, comment)
     VALUES ($1, $2, $3, $4)
     RETURNING *`,
    [match_id, userId, rating, comment]
  );

  return res.json(r.rows[0]);
});

export default router;