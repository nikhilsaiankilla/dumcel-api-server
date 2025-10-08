import { Response } from "express";
import { z } from "zod";
import { RunTaskCommand } from "@aws-sdk/client-ecs";
import { ProjectModel } from "../model/project.model";
import { generateSlug } from "random-word-slugs";
import { DeploymentModel, DeploymentState } from "../model/deployment.model";
import { AuthenticatedRequest } from "../middleware/auth.middleware";

export const projectController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const schema = z.object({
            name: z.string(),
            gitUrl: z.string(),
            subDomain: z.string().optional(),
        });

        const userId = req?.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const safeParseResult = schema.safeParse(req.body);
        if (!safeParseResult.success) throw new Error(safeParseResult.error.message || "Required All Fields");

        const { name, gitUrl, subDomain } = safeParseResult.data;

        const project = await ProjectModel.create({
            projectName: name,
            userId: userId, // TODO: Replace with actual user later
            gitUrl,
            subDomain: subDomain ? subDomain : generateSlug(),
        });

        return res.json({ status: "success", data: { project } });
    } catch (error) {
        return res.json({ status: "failed", error: error instanceof Error ? error.message : "Something went wrong" });
    }
};

export const deployController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const secrets = global.secrets;

        const { projectId } = req.params;
        const project = await ProjectModel.findById(projectId);
        if (!project) throw new Error("Project Not Found");

        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const deployment = await DeploymentModel.create({
            projectId: projectId,
            state: DeploymentState.QUEUED,
        });

        // Ensure secrets are available before using them
        if (!secrets) throw new Error("Server secrets not initialized");

        // Use ECS client instance created after secrets are fetched
        const command = new RunTaskCommand({
            cluster: secrets.CLUSTER,
            taskDefinition: secrets.TASK,
            launchType: "FARGATE",
            count: 1,
            networkConfiguration: {
                awsvpcConfiguration: {
                    assignPublicIp: "ENABLED",
                    subnets: [
                        secrets.subnets_1,
                        secrets.subnets_2,
                        secrets.subnets_3,
                    ],
                    securityGroups: [secrets.security_group],
                },
            },
            overrides: {
                containerOverrides: [
                    {
                        name: secrets.builder_image,
                        environment: [
                            { name: "GIT_REPO_URL", value: project.gitUrl },
                            { name: "PROJECT_ID", value: projectId },
                            { name: "DEPLOYMENT_ID", value: deployment.id },
                            { name: "SUB_DOMAIN", value: project.subDomain },
                        ],
                    },
                ],
            },
        });

        await global.ecsClient.send(command);

        return res.json({
            status: "Queued",
            data: {
                projectId: projectId,
                deploymentId: deployment.id,
                subDomain: project.subDomain,
            },
        });
    } catch (error) {
        console.log("error ", error);
        return res.status(400).json({ error: error instanceof Error ? error.message : "Internal Server Error" });
    }
};

export const logsController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const { deploymentId } = req.params;

        if (!deploymentId) throw new Error("Deployment ID is required");

        const logs = await global.clickhouseClient.query({
            query: `SELECT event_id, deployment_id, log, timestamp FROM log_events WHERE deployment_id = ${deploymentId} ORDER BY timestamp DESC`,
            query_params: {
                deployment_id: deploymentId,
            },
            format: "JSONEachRow",
        });

        const rawlogs = await logs.json();

        return res.json({ status: "success", data: { logs: rawlogs } });
    } catch (error: unknown) {
        return res.status(400).json({ status: "failed", error: error instanceof Error ? error.message : "Internal Server Error" });
    }
};

export const getProjectController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const { projectId } = req.params;

        if (!projectId) throw new Error("Project ID is required");

        const project = await ProjectModel.findById(projectId);

        if (!project) throw new Error('Project Not Found');

        return res.json({ status: "success", project: project });
    } catch (error: unknown) {
        return res.status(400).json({ status: "failed", error: error instanceof Error ? error.message : "Internal Server Error" });
    }
}

export const getAllProjectsController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;

        const skip = (page - 1) * 10;

        const [projects, totalCount] = await Promise.all([
            ProjectModel.find({ userId })
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit),
            ProjectModel.countDocuments({ userId })
        ])

        return res.json({
            status: "success",
            data: {
                projects,
                pagination: {
                    total: totalCount,
                    page,
                    limit,
                    totalPages: Math.ceil(totalCount / limit),
                    hasNextPage: page * limit < totalCount,
                    hasPrevPage: page > 1,
                },
            },
        });
    } catch (error: unknown) {
        return res.status(400).json({ status: "failed", error: error instanceof Error ? error.message : "Internal Server Error" });
    }
}