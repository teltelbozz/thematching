import { Router } from 'express';
import type { Pool } from 'pg';

const router = Router();

// GET /slots
router.get('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const r = await db.query(`
    SELECT id, title, theme, date_time, venue, location_lat, location_lng,
           capacity, fee_yen, is_online
    FROM party_slots
    ORDER BY id DESC
  `);
  return res.json(r.rows);
});

// POST /slots
router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const {
    title, theme, date_time, venue,
    location_lat, location_lng, capacity, fee_yen, is_online
  } = req.body;

  const sql = `
    INSERT INTO party_slots
      (host_user_id, title, theme, date_time, venue,
       location_lat, location_lng, capacity, fee_yen, is_online, visibility)
    VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, 'public')
    RETURNING *
  `;
  const r = await db.query(sql, [
    title, theme, date_time, venue,
    location_lat, location_lng, capacity, fee_yen, is_online
  ]);
  return res.json(r.rows[0]);
});

// POST /slots/:id/join
router.post('/:id/join', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const userId = (req as any).userId || 1; // devAuth で付与される
  const slotId = Number(req.params.id);

  const sql = `
    INSERT INTO slot_participants (slot_id, user_id)
    VALUES ($1, $2)
    ON CONFLICT DO NOTHING
    RETURNING *
  `;
  await db.query(sql, [slotId, userId]);
  return res.json({ ok: true });
});

export default router;