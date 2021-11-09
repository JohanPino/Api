import { serverMessagesToUser, userManagementStatus } from "../general/general.js";
import { connection } from '../database/connection.js';
import jsonwebtoken from 'jsonwebtoken';
import { ENCRYPTION_SECRET_KEY } from '../config/config.js';


export const userManagement = {
    async signUp(req, res) {
        let query;
        try {
            connection.connect(async (err, client, done) => {
                try {
                    query = {
                        text: "select * from f_validate_insert_user($1)",
                        values: [req.body.email]
                    };
                    if (err) {
                        res.json(serverMessagesToUser.readMessage(1003, err.message));
                    } else {
                        client.query(query, async (err, results) => {
                            if (!err) {
                                const estadoUsuario = results.rows[0].f_validate_insert_user;
                                if (estadoUsuario === userManagementStatus.emailExists) {
                                    res.json(serverMessagesToUser.readMessage(1012));
                                } else {
                                    query = {
                                        text: "select * from f_insert_user($1)",
                                        values: [req.body]
                                    };
                                    client.query(query, async (err, results) => {
                                        if (!err) {
                                            res.json(serverMessagesToUser.readMessage(1002));
                                        } else {
                                            res.json(serverMessagesToUser.readMessage(1003, err.message));
                                        }
                                    });
                                }
                            } else {
                                res.json(serverMessagesToUser.readMessage(1003, err.message));
                            }
                        });
                    }
                } finally {
                    done();
                    query = {}
                }
            });
        } catch (error) {
            res.json(serverMessagesToUser.readMessage(1003, error.message));
        }
    },
    async login(req, res) {
        let query;
        try {
            query = {
                text: "select * from f_validate_auth($1)",
                values: [req.body]
            };
            connection.connect(async (err, client, done) => {
                try {
                    if (err) {
                        res.json(serverMessagesToUser.readMessage(1005, err.message));
                    } else {
                        client.query(query, async (err, results) => {
                            if (err) {
                                res.json(serverMessagesToUser.readMessage(1005, err.message));
                            } else {
                                switch (results.rows[0].f_validate_auth) {
                                    case userManagementStatus.doesNotExist:
                                        res.json(serverMessagesToUser.readMessage(1008));
                                        break;
                                    case userManagementStatus.wrongLoginData:
                                        res.json(serverMessagesToUser.readMessage(1006));
                                        break;
                                    default:
                                        query = {
                                            text: "select * from f_user_auth($1,$2)",
                                            values: [req.body.email, req.body.password]
                                        };
                                        client.query(query, async (err, results) => {
                                            if (!err) {
                                                jsonwebtoken.sign(results.rows[0], ENCRYPTION_SECRET_KEY, (jwtErr, token) => {
                                                    if (!jwtErr) {
                                                        res.status(200).json({
                                                            token
                                                        });
                                                    } else {
                                                        res.json(serverMessagesToUser.readMessage(1005, jwtErr.message));
                                                    }
                                                });

                                            } else {
                                                res.json(serverMessagesToUser.readMessage(1005, err.message));
                                            }
                                        });
                                }
                            }
                        });
                    }
                } finally {
                    done();
                    query = {};
                }
            });
        } catch (error) {
            res.json(serverMessagesToUser.readMessage(1005, error.message));
        }
    },
    async updatePassword(req, res) {
        let query;
        try {
            query = {
                text: "select * from f_validate_update_pass_user($1, $2)",
                values: [req.body.password, req.body.id]
            };
            connection.connect(async (err, client, done) => {
                try {
                    if (err) {
                        res.json(serverMessagesToUser.readMessage(1024, err.message));
                    } else {
                        client.query(query, async (err, results) => {
                            if (err) {
                                res.json(serverMessagesToUser.readMessage(1024, err.message));
                            } else {
                                switch (results.rows[0].f_validate_update_pass_user) {
                                    case userManagementStatus.passwordExist:
                                        res.json(serverMessagesToUser.readMessage(1026));
                                        break;
                                    case userManagementStatus.doesNotExist:
                                        query = {
                                            text: "select * from f_update_user_password($1, $2, $3)",
                                            values: [req.body.id, req.body.password, req.body.max_logon_times]
                                        };
                                        client.query(query, async (err, results) => {
                                            if (!err) {
                                                res.json(serverMessagesToUser.readMessage(1025));
                                            } else {
                                                res.json(serverMessagesToUser.readMessage(1024, err.message));
                                            }
                                        });
                                        break;
                                }
                            }
                        });
                    }
                } finally {
                    done();
                    query = {}
                }
            });
        } catch (error) {
            res.json(serverMessagesToUser.readMessage(1024, error.message));
        }
    }
}