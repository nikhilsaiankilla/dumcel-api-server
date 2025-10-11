import express from "express";
import { deployController, getAllDeploymentsController, getAllProjectsController, getProjectController, logsController, projectController } from "../controller/project.controller";
import { authMiddleware } from "../middleware/auth.middleware";

const router = express.Router();

router.get('/get-all-projects', authMiddleware, getAllProjectsController);

router.get('/getProject/:projectId', authMiddleware, getProjectController);

router.post('/add-project', authMiddleware, projectController);

router.post('/deploy/:projectId', authMiddleware, deployController)

router.get('/logs/:deploymentId', authMiddleware, logsController);

router.get('/get-all-deployments', authMiddleware, getAllDeploymentsController)

export const projectRouter = router;
