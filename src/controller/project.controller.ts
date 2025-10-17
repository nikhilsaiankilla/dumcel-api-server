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
            userId: userId,
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
        if (!userId) throw new Error('Unauthenticated User');

        const { deploymentId } = req.params;
        const { lastTimestamp, limit } = req.query;

        if (!deploymentId) throw new Error("Deployment ID is required");

        // Default values
        const limitValue = Number(limit) || 500; // fetch up to 500 lines at once
        const lastTimestampValue = lastTimestamp || "1970-01-01 00:00:00";

        // Query ClickHouse
        const query = `
            SELECT 
                event_id, 
                project_id, 
                deployment_id, 
                log, 
                timestamp, 
                type, 
                step, 
                meta
            FROM log_events
            WHERE deployment_id = {deployment_id:String}
            AND timestamp > {lastTimestamp:DateTime}
            ORDER BY timestamp ASC
            LIMIT {limit:Int32}
        `;

        const logsResponse = await global.clickhouseClient.query({
            query,
            query_params: {
                deployment_id: deploymentId,
                lastTimestamp: lastTimestampValue,
                limit: limitValue
            },
            format: "JSONEachRow",
        });

        const rawLogs = await logsResponse.json();

        // Send result
        return res.json({
            status: "success",
            data: {
                count: rawLogs.length,
                lastTimestamp:
                    rawLogs.length > 0 ? rawLogs[rawLogs.length - 1].timestamp : lastTimestampValue,
                logs: rawLogs
            },
        });

    } catch (error: unknown) {
        console.error("Error fetching logs:", error);
        return res.status(400).json({
            status: "failed",
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const getProjectController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) throw new Error('Unauthenticated User');

        const { projectId } = req.params;
        if (!projectId) throw new Error("Project ID is required");

        const project = await ProjectModel.findById(projectId).lean();
        if (!project) throw new Error('Project Not Found');

        const latestDeployment = await DeploymentModel.findOne({ projectId })
            .sort({ createdAt: -1 })
            .lean();

        const projectWithDeploymentId = {
            ...project,
            deployment: {
                latestDeploymentId: latestDeployment?._id || null,
                state: latestDeployment?.state || 'not started'
            }
        };

        return res.json({
            status: "success",
            project: projectWithDeploymentId,
        });
    } catch (error: unknown) {
        return res.status(400).json({
            status: "failed",
            error: error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const getAllProjectsController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;

        const skip = (page - 1) * limit;

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

export const getAllDeploymentsController = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;

        if (!userId) throw new Error('Unauthenticated User')

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const state = req.query.state as string | undefined;

        const skip = (page - 1) * limit;

        // Build filter object
        const filter: Record<string, any> = { userId };
        if (state) filter.state = state;

        const [deployments, totalCount] = await Promise.all([
            DeploymentModel.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .populate({
                    path: "projectId",
                    select: "_id projectName subDomain updatedAt",
                }),
            DeploymentModel.countDocuments(filter),
        ]);

        return res.json({
            status: "success",
            data: {
                deployments,
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

export const getAllDeploymentsForProjectController = async (
    req: AuthenticatedRequest,
    res: Response
) => {
    try {
        const userId = req.user?.userId;
        if (!userId) throw new Error("Unauthenticated User");

        const { projectId } = req.params;
        if (!projectId) throw new Error("Project ID is required");

        const page = parseInt(req.query.page as string) || 1;
        const limit = parseInt(req.query.limit as string) || 10;
        const state = req.query.state as string | undefined; // optional: e.g. "READY" | "FAILED" | "IN_PROGRESS"
        const skip = (page - 1) * limit;

        const filter: Record<string, any> = { projectId };
        if (state) filter.state = state; // optional filter by deployment state

        const [deployments, totalCount] = await Promise.all([
            DeploymentModel.find(filter)
                .sort({ createdAt: -1 })
                .skip(skip)
                .limit(limit)
                .populate({
                    path: "projectId",
                    select: "_id projectName subDomain updatedAt",
                }),
            DeploymentModel.countDocuments(filter),
        ]);

        return res.json({
            status: "success",
            data: {
                deployments,
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
        console.error("Error fetching project deployments:", error);
        return res.status(400).json({
            status: "failed",
            error:
                error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const deleteProjectHandler = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const userId = req.user?.userId;
        if (!userId) throw new Error("Unauthenticated User");

        const { projectId } = req.params;
        if (!projectId) throw new Error("Project ID is required");

        // Find project
        const project = await ProjectModel.findById(projectId);
        if (!project) {
            return res.status(404).json({
                status: "failed",
                message: "Project not found",
            });
        }

        // Ensure user owns the project
        if (project.userId.toString() !== userId) {
            return res.status(403).json({
                status: "failed",
                message: "You are not authorized to delete this project",
            });
        }

        // Delete the project
        await ProjectModel.findByIdAndDelete(projectId);

        return res.status(200).json({
            status: "success",
            message: "Project deleted successfully",
            projectId,
        });

    } catch (error: unknown) {
        console.error("Error deleting project:", error);
        return res.status(500).json({
            status: "failed",
            error:
                error instanceof Error ? error.message : "Internal Server Error",
        });
    }
};

export const checkSubDomain = async (req: AuthenticatedRequest, res: Response) => {
    try {
        const schema = z.object({
            subDomain: z
                .string()
                .min(1, "Subdomain is required")
                .regex(/^[a-z0-9-]+$/, "Subdomain must contain only lowercase letters, numbers, and hyphens"),
        });

        const { subDomain } = schema.parse(req.query);

        const existingProject = await ProjectModel.findOne({
            subdomain: subDomain
        });

        // 3. Send Response
        if (existingProject) {
            // The subdomain is taken
            return res.status(200).json({
                available: false,
                message: "Subdomain is already taken."
            });
        } else {
            // The subdomain is free
            return res.status(200).json({
                available: true,
                message: "Subdomain is available."
            });
        }
    } catch (error: unknown) {
        // Handle Zod validation errors or other errors
        if (error instanceof z.ZodError) {
            return res.status(400).json({
                error: 'Validation Error',
                message: error.message
            });
        }

        console.error("Error checking subdomain:", error);
        return res.status(500).json({
            error: 'Server Error',
            message: 'Failed to check subdomain availability.'
        });
    }
}