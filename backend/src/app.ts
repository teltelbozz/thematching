import express from 'express';
import cors from 'cors';

// ★ 重要：ESM では実行時の拡張子 .js を付ける
import healthRouter from './routes/health.js';
import slotsRouter from './routes/slots.js';
import matchesRouter from './routes/matches.js';
import chatsRouter from './routes/chats.js';
import reviewsRouter from './routes/reviews.js';
import authRouter from './routes/auth.js';

// devAuth を使っている場合（存在しない環境ではビルドされないように optional にしてもOK）
import devAuth from './middleware/devAuth.js';

const app = express();

/**
 * フロントの本番URL（CORS許可先）
 * 必要に応じて Vercel の環境変数 FRONT_ORIGIN に入れて上書きできます。
 */
const FRONT_ORIGIN =
  process.env.FRONT_ORIGIN || 'https://thematching-frontend.vercel.app';

// Vercel 経由で Secure Cookie を扱うために必須
app.set('trust proxy', 1);

/**
 * CORS（preflight を含め、Cookie を伴うクロスサイト通信を許可）
 * ※ origin はワイルドカードにしない（credentials:true と両立不可）
 */
const corsOptions: cors.CorsOptions = {
  origin: FRONT_ORIGIN,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
};
app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

app.use(express.json());

// 開発用の擬似認証（ON のときだけ有効）
if (devAuth) {
  app.use(devAuth);
}

// ルータ登録
app.use('/api/health', healthRouter);
app.use('/api/auth', authRouter);
app.use('/api/slots', slotsRouter);
app.use('/api/matches', matchesRouter);
app.use('/api/chats', chatsRouter);
app.use('/api/reviews', reviewsRouter);

export default app;