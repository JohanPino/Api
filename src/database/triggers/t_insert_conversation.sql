DROP TRIGGER IF EXISTS t_insert_passwords_log ON USERS;
CREATE TRIGGER t_insert_passwords_log
    AFTER INSERT OR UPDATE 
    ON USERS
    FOR EACH ROW
    EXECUTE PROCEDURE f_insert_passwords_log();