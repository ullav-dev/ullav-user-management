-- Grandfather all existing users into the Individual (Free) plan for Clann.
--
-- Any user who existed before the subscription system was introduced is given
-- an active Individual subscription.  The partial unique index on the
-- subscriptions table (status IN ('active','trialing','past_due')) ensures
-- this INSERT is idempotent — re-running the migration will not create
-- duplicate rows.

INSERT INTO subscriptions (user_id, product_id, plan, status)
SELECT u.id, p.id, 'individual', 'active'
FROM   users    u
CROSS  JOIN products p
WHERE  p.slug = 'clann'
ON CONFLICT DO NOTHING;
