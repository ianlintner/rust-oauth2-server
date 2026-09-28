ALTER TABLE transaction_authorizations ADD COLUMN acr_values TEXT NOT NULL DEFAULT '';
ALTER TABLE transaction_authorizations ADD COLUMN max_age INTEGER;
