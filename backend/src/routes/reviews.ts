import { Router } from 'express';
import type { Pool } from 'pg';
const router = Router();

router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const reviewerId = (req as any).userId;
  if (!reviewerId) return res.status(401).json({ error: 'unauthenticated' });
  const { reviewee_id, slot_id, rating, comment } = req.body;
  const { rows } = await db.query(`INSERT INTO reviews (reviewer_id, reviewee_id, slot_id, rating, comment)
                                   VALUES ($1,$2,$3,$4,$5) RETURNING *`, [reviewerId, reviewee_id, slot_id, rating, comment]);
  res.status(201).json(rows[0]);
});

export default router;