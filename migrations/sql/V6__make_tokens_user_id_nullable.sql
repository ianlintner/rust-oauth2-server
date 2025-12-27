-- Make tokens.user_id nullable so client_credentials tokens can be issued without a user
-- (OAuth2 client credentials grant is typically client-only.)

DO $$
BEGIN
    -- Drop NOT NULL if it exists; keep this migration safe to run across environments.
    BEGIN
        ALTER TABLE tokens ALTER COLUMN user_id DROP NOT NULL;
    EXCEPTION
        WHEN undefined_table THEN
            RAISE NOTICE 'Table tokens does not exist; skipping';
        WHEN undefined_column THEN
            RAISE NOTICE 'Column tokens.user_id does not exist; skipping';
        WHEN undefined_object THEN
            -- Happens if the column is already nullable.
            RAISE NOTICE 'Column tokens.user_id already nullable; skipping';
    END;
END $$;
