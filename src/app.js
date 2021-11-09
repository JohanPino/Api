import cors from'cors';
import express from'express';
import { application, SERVER_PORT } from './config/config.js';

//Routes
import userRouter from './routes/UserRoutes.js';

const app = express();


app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(cors(application.cors.server));


app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-API-KEY, Origin, X-Requested-With, Content-Type, Content-Disposition, Accept, Access-Control-Allow-Request-Method');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
    res.setHeader('Allow', 'GET, POST, OPTIONS, PUT, DELETE');
    next();
});



app.use('/api/userManagement', userRouter);

//ROUTES
app.set('port', process.env.PORT || SERVER_PORT);

export default app;
