import { Router } from 'express';
import type { Pool } from 'pg';
const router = Router();

router.get('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { from, to } = req.query as { from?: string; to?: string };
  const params: any[] = [];
  const where: string[] = [];
  if (from) { params.push(from); where.push(`date_time >= $${params.length}`); }
  if (to)   { params.push(to);   where.push(`date_time <= $${params.length}`); }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const sql = `SELECT id, title, theme, date_time, venue, capacity, fee_yen, is_online
               FROM party_slots ${whereSql}
               ORDER BY date_time ASC LIMIT 100`;
  const { rows } = await db.query(sql, params);
  res.json(rows);
});

router.post('/', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { title, theme, date_time, venue, location_lat, location_lng, capacity, fee_yen, is_online } = req.body;
  const sql = `INSERT INTO party_slots (host_user_id, title, theme, date_time, venue, location_lat, location_lng, capacity, fee_yen, is_online)
               VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, coalesce($9,false))
               RETURNING *`;
  const params = [title, theme, date_time, venue, location_lat, location_lng, capacity, fee_yen, is_online];
  const { rows } = await db.query(sql, params);
  res.status(201).json(rows[0]);
});

router.get('/:slotId', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { slotId } = req.params;
  const { rows } = await db.query('SELECT * FROM party_slots WHERE id = $1', [slotId]);
  if (!rows[0]) return res.status(404).json({ error: 'not_found' });
  res.json(rows[0]);
});

router.post('/:slotId/join', async (req, res) => {
  const db = req.app.locals.db as Pool;
  const { slotId } = req.params;
  const userId = 1; // TODO: replace by auth user (LINE)
  await db.query('INSERT INTO slot_participants (slot_id, user_id, role, status) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING', [slotId, userId, 'guest', 'pending']);
  res.json({ ok: true });
});

export default router;