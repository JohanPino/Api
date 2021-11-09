CREATE OR REPLACE FUNCTION f_user_auth(in_email TEXT, in_password TEXT)
RETURNS TABLE(
    user_id INTEGER,
    user_name VARCHAR(100),
    user_email VARCHAR(250),
    user_max_logon_times INTEGER 
   ) AS
$BODY$
DECLARE
	err_context TEXT;
BEGIN
        RETURN QUERY
            SELECT  id,
                    name,
                    email,
                    max_logon_times
            FROM USERS
            WHERE   email = in_email
            AND     password = in_password;

    EXCEPTION WHEN OTHERS THEN
        GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
        RAISE INFO 'Error Name:%',SQLERRM;
        RAISE INFO 'Error State:%', SQLSTATE;
        RAISE INFO 'Error Context:%', err_context;
END
$BODY$ LANGUAGE 'plpgsql'

