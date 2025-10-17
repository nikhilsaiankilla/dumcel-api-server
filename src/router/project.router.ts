import express from "express";
import { checkSubDomain, deleteProjectHandler, deployController, getAllDeploymentsController, getAllDeploymentsForProjectController, getAllProjectsController, getProjectController, logsController, projectController } from "../controller/project.controller";
import { authMiddleware } from "../middleware/auth.middleware";

const router = express.Router();

router.get('/get-all-projects', authMiddleware, getAllProjectsController);

router.delete('/delete/:projectId', authMiddleware, deleteProjectHandler)

router.get('/getProject/:projectId', authMiddleware, getProjectController);

router.post('/add-project', authMiddleware, projectController);

router.post('/deploy/:projectId', authMiddleware, deployController)

router.get('/logs/:deploymentId', authMiddleware, logsController);

router.get('/get-all-deployments', authMiddleware, getAllDeploymentsController)

router.get('/get-all-deployments/:projectId', authMiddleware, getAllDeploymentsForProjectController)

router.get('/check-subdomain', authMiddleware, checkSubDomain)

export const projectRouter = router;
