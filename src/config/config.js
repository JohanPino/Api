export const SERVER_PORT = 4000;
export const application = {
    cors: {
        server: [
            {
                origin: "*",
                credentials: true
            }
        ]
    }
};
export const DB_CREDENTIALS = {
    HEROKU: {
        user: "hktmlachjjpcup",
        host: "ec2-34-200-139-9.compute-1.amazonaws.com",
        database: "d7789m3k74vtjb",
        password: "cdcdf0d67292d2013eddbf344767340291a9826b95cf0a19d282d638526b49dc",
        port: 5432,
        ssl: { rejectUnauthorized: false },
    },
    LOCALHOST: {
        user: "",
        host: "",
        database: "",
        password: "",
        port: 5432
    },
    URI: "postgres://hktmlachjjpcup:cdcdf0d67292d2013eddbf344767340291a9826b95cf0a19d282d638526b49dc@ec2-34-200-139-9.compute-1.amazonaws.com:5432/d7789m3k74vtjb"
};
export const ENCRYPTION_SECRET_KEY = 'manejo-usuarios-claves';