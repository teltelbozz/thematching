import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';

const app = express();
app.use(cors());
app.use(express.json());

// Postgres pool
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
app.locals.db = pool;

// Routers
import healthRouter from './routes/health.js';
import slotsRouter from './routes/slots.js';
import matchesRouter from './routes/matches.js';
import chatsRouter from './routes/chats.js';
import reviewsRouter from './routes/reviews.js';

app.use('/api/health', healthRouter);
app.use('/api/slots', slotsRouter);
app.use('/api/matches', matchesRouter);
app.use('/api/chats', chatsRouter);
app.use('/api/reviews', reviewsRouter);

export default app;
