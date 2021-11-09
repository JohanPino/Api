CREATE OR REPLACE FUNCTION f_insert_user(in_json_user JSON)
    RETURNS void AS
    $BODY$
	DECLARE
		err_context TEXT;
    BEGIN

        INSERT INTO USERS(
            name,
            email,
            password,
            max_logon_times
        )
        SELECT
            name,
            email,
            password,
            max_logon_times
        FROM json_to_record(in_json_user) AS x( 
            name TEXT,
            email TEXT,
            password TEXT,
            max_logon_times INTEGER
        );

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
            RAISE INFO 'Error Name:%',SQLERRM;
            RAISE INFO 'Error State:%', SQLSTATE;
            RAISE INFO 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql'