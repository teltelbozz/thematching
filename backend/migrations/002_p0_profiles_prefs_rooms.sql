-- 002_p0_profiles_prefs_rooms.sql
-- Neon/Postgres 用（再実行OK）

-----------------------------
-- 共通: updated_at 自動更新
-----------------------------
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END; $$;

-----------------------------
-- 1) ユーザープロフィール
-----------------------------
CREATE TABLE IF NOT EXISTS user_profiles (
  user_id           BIGINT PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,
  nickname          TEXT NOT NULL,
  age               INT,
  gender            TEXT CHECK (gender IN ('male','female','other')) DEFAULT 'other',
  occupation        TEXT,
  photo_url         TEXT,
  photo_masked_url  TEXT,
  verified_age      BOOLEAN DEFAULT FALSE,
  tos_accepted_at   TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- updated_at トリガ
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_user_profiles_updated_at'
  ) THEN
    CREATE TRIGGER trg_user_profiles_updated_at
      BEFORE UPDATE ON user_profiles
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;

-- 参照に便利な index（必要に応じて）
CREATE INDEX IF NOT EXISTS idx_user_profiles_age      ON user_profiles(age);
CREATE INDEX IF NOT EXISTS idx_user_profiles_gender   ON user_profiles(gender);
CREATE INDEX IF NOT EXISTS idx_user_profiles_verified ON user_profiles(verified_age);

-----------------------------
-- 2) ユーザー希望条件
-----------------------------
-- 1ユーザー＝1レコード想定（最新版上書き運用）
CREATE TABLE IF NOT EXISTS user_preferences (
  id                BIGSERIAL PRIMARY KEY,
  user_id           BIGINT NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
  available_dates   JSONB,         -- 例: ["2025-09-20","2025-09-27"]
  areas             TEXT[],        -- 例: {"shibuya","ebisu"}
  age_min           INT,
  age_max           INT,
  appearance_tags   TEXT[],        -- 例: {"cute","simple"}
  occupation_tags   TEXT[],        -- 例: {"engineer","doctor"}
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT uq_user_preferences_user UNIQUE (user_id)
);

-- updated_at トリガ
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_user_preferences_updated_at'
  ) THEN
    CREATE TRIGGER trg_user_preferences_updated_at
      BEFORE UPDATE ON user_preferences
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;

-- 検索最適化（areas/appearance/occupation は配列 → GIN）
CREATE INDEX IF NOT EXISTS idx_user_prefs_areas_gin
  ON user_preferences USING GIN (areas);
CREATE INDEX IF NOT EXISTS idx_user_prefs_appearance_gin
  ON user_preferences USING GIN (appearance_tags);
CREATE INDEX IF NOT EXISTS idx_user_prefs_occupation_gin
  ON user_preferences USING GIN (occupation_tags);

-- available_dates は JSONB のまま GIN で柔軟に
CREATE INDEX IF NOT EXISTS idx_user_prefs_available_dates_gin
  ON user_preferences USING GIN (available_dates jsonb_path_ops);

-----------------------------
-- 3) ルームメンバー管理
-----------------------------
-- 既存のテーブル名は chat_rooms なので、そちらを参照
CREATE TABLE IF NOT EXISTS room_members (
  room_id   BIGINT NOT NULL REFERENCES chat_rooms(id) ON DELETE CASCADE,
  user_id   BIGINT NOT NULL REFERENCES users(id)      ON DELETE CASCADE,
  role      TEXT   NOT NULL DEFAULT 'guest' CHECK (role IN ('host','guest')),
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (room_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);

-----------------------------
-- 4) マッチング・ジョブ（簡易）
-----------------------------
CREATE TABLE IF NOT EXISTS match_jobs (
  id             BIGSERIAL PRIMARY KEY,
  scheduled_for  DATE NOT NULL,   -- 対象日（例: 開催日）
  status         TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','running','done','failed')),
  created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_match_jobs_updated_at'
  ) THEN
    CREATE TRIGGER trg_match_jobs_updated_at
      BEFORE UPDATE ON match_jobs
      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_match_jobs_scheduled_for ON match_jobs(scheduled_for);
CREATE INDEX IF NOT EXISTS idx_match_jobs_status        ON match_jobs(status);