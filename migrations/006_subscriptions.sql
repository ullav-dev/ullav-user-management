-- Central subscription registry shared across all Ullav products.
--
-- One active/trialing subscription is permitted per user per product (enforced
-- by the partial unique index).  Cancelled or pending rows are retained for
-- audit purposes and are not covered by the uniqueness constraint.

CREATE TABLE IF NOT EXISTS subscriptions (
    id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                     UUID        NOT NULL REFERENCES users(id)    ON DELETE CASCADE,
    product_id                  UUID        NOT NULL REFERENCES products(id) ON DELETE RESTRICT,
    plan                        TEXT        NOT NULL DEFAULT 'individual',
    status                      TEXT        NOT NULL DEFAULT 'active'
                                                CHECK (status IN ('active','trialing','past_due','cancelled','pending')),
    payment_provider            TEXT        CHECK (payment_provider IN ('stripe','paypal','manual')),
    provider_subscription_id    TEXT,
    provider_customer_id        TEXT,
    seat_count                  SMALLINT    NOT NULL DEFAULT 1 CHECK (seat_count >= 1),
    trial_end                   TIMESTAMPTZ,
    current_period_start        TIMESTAMPTZ,
    current_period_end          TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Prevent duplicate active subscriptions for the same user+product.
CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_user_product_active
    ON subscriptions (user_id, product_id)
    WHERE status IN ('active', 'trialing', 'past_due');

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id
    ON subscriptions (user_id);

CREATE INDEX IF NOT EXISTS idx_subscriptions_product_id
    ON subscriptions (product_id);

-- Fast lookup by provider subscription ID (used by webhook handlers).
CREATE INDEX IF NOT EXISTS idx_subscriptions_provider_sub_id
    ON subscriptions (provider_subscription_id)
    WHERE provider_subscription_id IS NOT NULL;

-- ── Seats ────────────────────────────────────────────────────────────────────
-- Tracks individual seat assignments within a multi-seat subscription
-- (Family/Team plan).  Each row is either a pending invitation (invited_email
-- set, member_user_id null) or an accepted seat (member_user_id set).

CREATE TABLE IF NOT EXISTS subscription_seats (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id UUID        NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    invited_email   TEXT,
    member_user_id  UUID        REFERENCES users(id) ON DELETE SET NULL,
    accepted_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sub_seats_subscription_id
    ON subscription_seats (subscription_id);

CREATE INDEX IF NOT EXISTS idx_sub_seats_member_user_id
    ON subscription_seats (member_user_id)
    WHERE member_user_id IS NOT NULL;
