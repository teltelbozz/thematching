import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Pool } from 'pg';
import devAuth from './middleware/devAuth.js';

const app = express();
app.use(cors());
app.use(express.json());

// Postgres pool
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
app.locals.db = pool;

// ★ devAuth を全ルートの前に適用（DEV_FAKE_AUTH=1 のときだけ有効）
app.use(devAuth);

// Routers
import healthRouter from './routes/health.js';
import slotsRouter from './routes/slots.js';
import matchesRouter from './routes/matches.js';
import chatsRouter from './routes/chats.js';
import reviewsRouter from './routes/reviews.js';
import authRouter from './routes/auth.js';

app.use('/api/auth', authRouter);
app.use('/api/health', healthRouter);
app.use('/api/slots', slotsRouter);
app.use('/api/matches', matchesRouter);
app.use('/api/chats', chatsRouter);
app.use('/api/reviews', reviewsRouter);

export default app;
