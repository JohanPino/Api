CREATE OR REPLACE FUNCTION f_validate_update_pass_user(in_new_pass TEXT, in_row_id_user INTEGER)
    RETURNS INTEGER
    AS
    $BODY$
        DECLARE
            err_context TEXT;
            v_err_code  INTEGER := 0; /*0 no existe, 4 pass existe*/

    BEGIN

        IF EXISTS 
        (
            SELECT  1 
            FROM    PASSWORDS_LOG
            WHERE   user_id = in_row_id_user
            AND     password = in_new_pass

        ) THEN
            v_err_code := 4;
        END IF;

        RETURN v_err_code;

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
            RAISE INFO 'Error Name:%',SQLERRM;
            RAISE INFO 'Error State:%', SQLSTATE;
            RAISE INFO 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql'