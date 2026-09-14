-- MAPPS-674: grant `payment_methods:manage_own` to the built-in Billing
-- Contact role, so a contact who already holds `invoices:pay` can also
-- save, list, remove and re-default their own cards.
--
-- Same append + de-dupe shape as 179, 199 and 217, scoped on
-- `is_builtin` so a tenant that renamed or customised the row is not
-- touched. Support Contact and Read-Only are deliberately left as they
-- are: saving a card is a Billing Contact action, and paying is where
-- the flow starts.
--
-- `contact_portal::capabilities::BUILTIN_BILLING_CONTACT` gains the same
-- string in the same PR; `builtin_roles_match_the_seed_migrations`
-- fails the build if the two disagree.

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'payment_methods:manage_own'
    ]::text[])
)
WHERE name = 'Billing Contact' AND is_builtin = TRUE;
