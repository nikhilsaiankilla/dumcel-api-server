import express, { Request, Response } from "express";
import { projectRouter } from './router/project.router';
import { authenticationRouter } from "./router/authentication.router";
import { connectDb } from "./utils/connectDb";
import cookieParser from "cookie-parser";
import { initSecrets } from "./utils/secrets";
import { DeploymentModel, DeploymentState } from "./model/deployment.model";
import { v4 } from 'uuid'
import { initConfigs } from "./utils/initConfigs";

const app = express();
app.use(express.json());
app.use(cookieParser());

// ---------- Kafka Consumer Setup ----------
interface KafkaClient {
    consumer: (options: { groupId: string }) => Consumer;
}

interface Consumer {
    connect(): Promise<void>;
    subscribe(options: { topic: string; fromBeginning: boolean }): Promise<void>;
    run(options: { eachBatch: (payload: EachBatchPayload) => Promise<void> }): Promise<void>;
}

interface EachBatchPayload {
    batch: Batch;
    heartbeat: () => Promise<void>;
    commitOffsetsIfNecessary: (offset: string) => Promise<void> | void;
    resolveOffset: (offset: string) => void;
}

interface Batch {
    messages: Message[];
}

interface Message {
    value: Buffer | string | null;
    key?: Buffer | string | null;
    offset: string;
}

interface ClickHouseClient {
    insert(options: {
        table: string;
        values: Record<string, unknown>[];
        format?: string;
    }): Promise<ClickHouseInsertResult>;
}

interface ClickHouseInsertResult {
    // minimal shape — expand if you need more fields from the CH driver result
    rows?: number;
    [key: string]: unknown;
}

interface LogPayload {
    PROJECT_ID: string;
    DEPLOYMENT_ID: string;
    log: string;
}

interface DeploymentStatusPayload {
    DEPLOYMENT_ID: string;
    STATUS: string;
}

async function initKafkaConsumer(kafka: KafkaClient, clickhouseClient: ClickHouseClient): Promise<void> {
    const consumer: Consumer = kafka.consumer({ groupId: 'api-server-logs-consumer' });

    await consumer.connect();
    await consumer.subscribe({ topic: 'container-log', fromBeginning: false });
    await consumer.subscribe({ topic: 'deployment-status-events', fromBeginning: false });

    await consumer.run({
        eachBatch: async function ({ batch, heartbeat, commitOffsetsIfNecessary, resolveOffset }: EachBatchPayload) {
            const messages: Message[] = batch.messages;

            for (const message of messages) {
                const stringMessages: string = message.value!.toString();
                const key: string | undefined = message.key?.toString();

                try {
                    if (key === 'logs') {
                        // Insert logs into ClickHouse
                        const { PROJECT_ID, DEPLOYMENT_ID, log } = JSON.parse(stringMessages) as LogPayload;

                        console.log("Log Message: ", log);

                        const res: ClickHouseInsertResult = await clickhouseClient.insert({
                            table: 'log_events',
                            values: [{
                                event_id: v4(),
                                deployment_id: DEPLOYMENT_ID,
                                log: typeof log === "string" ? log : JSON.stringify(log)
                            }],
                            format: 'JSONEachRow'
                        });

                        console.log('res ', res);

                    } else if (key === 'deployment-status') {
                        // Update deployment status in MongoDB
                        const { DEPLOYMENT_ID, STATUS } = JSON.parse(stringMessages) as DeploymentStatusPayload;

                        let DEPLOYMENT_STATUS: any = DeploymentState.QUEUED;

                        if (STATUS === 'failed') DEPLOYMENT_STATUS = DeploymentState.FAILED;
                        else if (STATUS === 'success') DEPLOYMENT_STATUS = DeploymentState.READY;
                        else if (STATUS === 'in_progress') DEPLOYMENT_STATUS = DeploymentState.IN_PROGRESS;

                        await DeploymentModel.findByIdAndUpdate(
                            { _id: DEPLOYMENT_ID },
                            { $set: { state: DEPLOYMENT_STATUS } }
                        );
                    }

                    commitOffsetsIfNecessary(message.offset);
                    resolveOffset(message.offset);
                    await heartbeat();
                } catch (error) {
                    console.error(`Error processing message:`, error);
                }
            }
        }
    });
}

app.get("/", (req: Request, res: Response) => {
    res.send("Hello TypeScript with Node.js and Express!");
});

app.use("/api/auth", authenticationRouter);

app.use("/api/project", projectRouter);

const PORT = process.env.PORT || 3000;

app.listen(PORT, async () => {
    await initSecrets();
    await connectDb()
    initConfigs();

    await initKafkaConsumer(global.kafka, global.clickhouseClient)
    console.log(`Server running on port ${PORT}`)
});
