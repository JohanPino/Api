import { Router } from 'express';
import { userManagement } from "../controllers/UserController.js";

const userRouter = Router();


userRouter.route('/signUp')
    .post(userManagement.signUp)

userRouter.route('/login')
    .post(userManagement.login)

userRouter.route('/updatePassword')
    .post(userManagement.updatePassword)

export default userRouter;