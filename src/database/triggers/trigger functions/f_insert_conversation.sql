CREATE OR REPLACE FUNCTION f_insert_passwords_log()
RETURNS TRIGGER AS 
$BODY$
    DECLARE
        err_context TEXT;
BEGIN

    IF (TG_OP = 'INSERT') THEN
        INSERT INTO PASSWORDS_LOG(
            user_id,
            password
        )VALUES(
            NEW.id,
            NEW.password
        );
    ELSIF (TG_OP = 'UPDATE' AND OLD.password <> NEW.password) THEN
        INSERT INTO PASSWORDS_LOG(
            user_id,
            password
        )VALUES(
            NEW.id,
            NEW.password
        );
    END IF;

RETURN NEW;

    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
		    RAISE EXCEPTION 'Error Name:%',SQLERRM;
            RAISE EXCEPTION 'Error State:%', SQLSTATE;
            RAISE EXCEPTION 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql'