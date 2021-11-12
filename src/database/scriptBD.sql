-- Se borran las tablas por si ya estan creadas.
DROP TABLE IF EXISTS USERS, PASSWORDS_LOG;

--Tables
CREATE TABLE USERS(
    ts_creation TIMESTAMP NOT NULL DEFAULT NOW()::TIMESTAMP,
    id SERIAL NOT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(250) NOT NULL, 
    password VARCHAR NOT NULL,
    max_logon_times INTEGER NOT NULL, 
    CONSTRAINT USERS_PK
        PRIMARY KEY (id),
    CONSTRAINT USERS_EMAIL_NO_REPEAT UNIQUE(email)
);

CREATE TABLE PASSWORDS_LOG(
    ts_creation TIMESTAMP NOT NULL DEFAULT NOW()::TIMESTAMP,
    id SERIAL NOT NULL,
    user_id INTEGER NOT NULL,
    password VARCHAR NOT NULL,
    CONSTRAINT PASSWORDS_LOG_PK
        PRIMARY KEY (id),
    CONSTRAINT PASSWORDS_LOG_FK_USERS
        FOREIGN KEY (user_id)
        REFERENCES USERS(id)
        ON UPDATE CASCADE
        ON DELETE CASCADE
);
--Tables

--storedProcedures
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
$BODY$ LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION f_update_user_password(in_row_id_user INTEGER, in_password TEXT,
                                                  in_max_logon_times INTEGER)
    RETURNS void AS
    $BODY$
	DECLARE
		err_context TEXT;
    BEGIN

        UPDATE USERS
        SET
            password = in_password,
            max_logon_times = in_max_logon_times
        WHERE id = in_row_id_user;

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
            RAISE INFO 'Error Name:%',SQLERRM;
            RAISE INFO 'Error State:%', SQLSTATE;
            RAISE INFO 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql';

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
$BODY$ LANGUAGE 'plpgsql';

CREATE OR REPLACE FUNCTION f_validate_auth(in_json_txt JSON)
    RETURNS INTEGER
    AS
    $BODY$
        DECLARE
            err_context TEXT;
            v_err_code INTEGER := 0; /*0 no existe, 1 datos incorrectos, 3 existe y correcto*/
            v_email TEXT;
			v_password TEXT;     
    BEGIN
	
    SELECT email INTO v_email 
    FROM json_to_record(in_json_txt) AS x(email TEXT);

        IF EXISTS (
            SELECT  1 
            FROM    USERS
            WHERE   email = v_email
        ) THEN

            SELECT password INTO v_password 
            FROM json_to_record(in_json_txt) AS x(password TEXT);

            IF EXISTS (
                SELECT  1 
                FROM    USERS
                WHERE   email       = v_email
                AND     password    = v_password
            ) THEN
                v_err_code := 3;
                
                UPDATE USERS
                SET max_logon_times = max_logon_times - 1
                WHERE email = v_email
                AND password    = v_password;
            ELSE
                v_err_code := 1;
            END IF;           
        ELSE
            v_err_code := 0;
        END IF;

        RETURN v_err_code;

        EXCEPTION WHEN OTHERS THEN
            GET STACKED DIAGNOSTICS err_context = PG_EXCEPTION_CONTEXT;
            RAISE INFO 'Error Name:%',SQLERRM;
            RAISE INFO 'Error State:%', SQLSTATE;
            RAISE INFO 'Error Context:%', err_context;

    END
$BODY$ LANGUAGE 'plpgsql';

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
$BODY$ LANGUAGE 'plpgsql';

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
$BODY$ LANGUAGE 'plpgsql';
--storedProcedures

--Triggers 

DROP TRIGGER IF EXISTS t_insert_passwords_log ON USERS;
CREATE TRIGGER t_insert_passwords_log
    AFTER INSERT OR UPDATE 
    ON USERS
    FOR EACH ROW
    EXECUTE PROCEDURE f_insert_passwords_log();

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
$BODY$ LANGUAGE 'plpgsql';
--Triggers