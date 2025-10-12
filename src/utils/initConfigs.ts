import { ECSClient } from "@aws-sdk/client-ecs";
import { Kafka } from "kafkajs";
import path from "path";
import fs from 'fs'
import { createClient } from "@clickhouse/client";

declare global {
    var ecsClient: any | undefined;
    var kafka: any | undefined;
    var clickhouseClient: any | undefined;
}

export const initConfigs = () => {
    const secrets = global.secrets;

    if (!secrets || !secrets.accessKeyId || !secrets.secretAccessKey || !secrets.kafka_ca_certificate) {
        throw new Error("AWS secrets are not configured on global.secrets");
    }

    const ecsClient = new ECSClient({
        region: "ap-south-1",
        credentials: {
            accessKeyId: secrets.accessKeyId,
            secretAccessKey: secrets.secretAccessKey
        }
    });

    const kafka = new Kafka({
        clientId: `api-server`,
        brokers: [secrets.kafka_broker],
        ssl: {
            rejectUnauthorized: false,
            ca: [secrets.kafka_ca_certificate.trim()]
        },
        sasl: {
            username: secrets.kafka_user_name,
            password: secrets.kafka_password,
            mechanism: "plain"
        }
    });

    const clickhouseClient = createClient({
        url: secrets.clickhouse_url,
        database: secrets.database,
        username: secrets.clickhouse_user_name,
        password: secrets.clickhouse_password
    });

    global.ecsClient = ecsClient;
    global.kafka = kafka;
    global.clickhouseClient = clickhouseClient;

    console.log('Intialised the clickhouse and kafka');
} 