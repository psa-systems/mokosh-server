-- MAPPS-1102: drop the `point_of_sale` capability.
--
-- The variant was removed from `Capability` in mokosh-types and from
-- Stripe's `supported_capabilities` in the integrations registry. Any
-- existing row that persisted the string in its `enabled_capabilities`
-- array becomes a reader-side mismatch: the enum will refuse to deserialize
-- the value, and silently dropping it leaves the admin UI showing fewer
-- delegations than the row claims.
--
-- Clear it here. The column is `text[]`; `array_remove` leaves the other
-- values in place and the row's `updated_at` on `integrations` is left
-- alone (this is not a tenant action).
--
-- A row that held ONLY `point_of_sale` becomes `enabled_capabilities = {}`,
-- which is the honest state: whatever the admin thought they were
-- delegating is no longer a thing this build serves.
--
-- No rollback path: re-adding POS means a scoped ticket (own subsystem +
-- Stripe Terminal / Square client, per MAPPS-1102's acceptance criteria),
-- not re-inserting the string.

UPDATE integrations
SET enabled_capabilities = array_remove(enabled_capabilities, 'point_of_sale')
WHERE 'point_of_sale' = ANY(enabled_capabilities);
