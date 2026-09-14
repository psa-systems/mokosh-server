-- MAPPS-673: grant `invoices:pay_partial` to the built-in Billing Contact
-- role, so a portal contact that already holds `invoices:pay` can mint a
-- partial-amount checkout as well as a full-balance one.
--
-- Same append + de-dupe shape as 179 and 199, scoped on `is_builtin` so a
-- tenant that renamed or customised the row is not touched. Support
-- Contact and Read-Only are deliberately left as they are: paying an
-- invoice is a Billing Contact action, and neither of the other two roles
-- carries `invoices:pay` today.
--
-- `contact_portal::capabilities::BUILTIN_BILLING_CONTACT` gains the same
-- string in the same PR; `builtin_roles_match_the_seed_migrations` fails
-- the build if the two disagree.

UPDATE portal_roles
SET capabilities = ARRAY(
    SELECT DISTINCT unnest(capabilities || ARRAY[
        'invoices:pay_partial'
    ]::text[])
)
WHERE name = 'Billing Contact' AND is_builtin = TRUE;
