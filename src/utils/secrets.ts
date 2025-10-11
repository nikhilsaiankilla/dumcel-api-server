// utils/secrets.ts
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const secretName = "production/dumcel/secrets";
const clientSecrets = new SecretsManagerClient({ region: "ap-south-1" });

let cachedSecrets: Record<string, any> | null = null;

declare global {
    var secrets: Record<string, any> | undefined;
}

/**
 * Initialize and cache secrets globally
 */
export async function initSecrets(): Promise<void> {
    if (global.secrets) {
        console.log("Secrets already initialized.");
        return;
    }

    try {
        const response = await clientSecrets.send(
            new GetSecretValueCommand({
                SecretId: secretName,
                VersionStage: "AWSCURRENT",
            })
        );

        if (!response.SecretString) throw new Error("SecretString is empty");

        const parsed = JSON.parse(response.SecretString);
        global.secrets = parsed;
        cachedSecrets = parsed;

        console.log("Secrets loaded and cached globally");
    } catch (error) {
        console.error("Failed to fetch secrets from Secrets Manager", error);
        throw error;
    }
}

/**
 * Retrieve cached secrets (after init)
 */
export function getSecrets(): Record<string, any> {
    if (!global.secrets && !cachedSecrets) {
        throw new Error("Secrets not initialized. Call initSecrets() first.");
    }
    return global.secrets || cachedSecrets!;
}
