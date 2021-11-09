CREATE OR REPLACE FUNCTION f_validate_insert_user(in_email TEXT)
    RETURNS INTEGER
    AS
    $BODY$
        DECLARE
            err_context TEXT;
            v_err_code INTEGER := 0; /*0 no existe, 2 email existe*/

    BEGIN

        IF EXISTS 
        (
            SELECT 1 
            FROM USERS
            WHERE email = in_email

        ) THEN
            v_err_code := 2;
        END IF;

        RETURN v_err_code;

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
            RAISE INFO 'Error Name:%',SQLERRM;
            RAISE INFO 'Error State:%', SQLSTATE;
            RAISE INFO 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql'