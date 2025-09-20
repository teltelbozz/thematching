# Backend (Vercel Ready)

## Local Dev
```bash
cp .env.example .env      # set DATABASE_URL
npm install
npm run migrate           # or run migrations/001_schema.sql in Neon SQL editor
npm run dev               # http://localhost:3000/api/health
```

## Deploy to Vercel
1) Push this `backend/` to GitHub (or configure monorepo with Root Directory `backend/`).
2) In Vercel Project → Settings → Environment Variables:
   - `DATABASE_URL` = your Neon connection string (include sslmode=require)
3) Deploy.
4) Check `https://<project>.vercel.app/api/health` → `{ ok: true }`

This project uses default export (`src/index.ts`) so Vercel runs the Express app automatically.
