import pg from 'pg';
import { DB_CREDENTIALS } from '../config/config.js';

export const connection = new pg.Pool(
    DB_CREDENTIALS.HEROKU
);

connection.connect(async (err, client, done) => {
    try {
        if (err) {
            console.log(err.message);
        } else {
            console.log("Conexion a base de datos exitosa");
        }
    } catch (err) {
        console.log(err.message);
    } finally {
        done();
    }
});
