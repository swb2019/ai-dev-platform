export type SystemStatus = {
  status: string;
  services: string[];
  timestamp: string;
};

const DEFAULT_INTERNAL_BASE_URL =
  "http://api-gateway.ai-dev-platform.svc.cluster.local";
const DEVELOPMENT_FALLBACK_URL = "http://localhost:4000";

function normalizeBaseUrl(candidate: string): string {
  const trimmed = candidate.trim();
  if (trimmed.endsWith("/")) {
    return trimmed.slice(0, -1);
  }
  return trimmed;
}

function resolveBaseUrl(): string {
  const configuredUrl =
    process.env.API_GATEWAY_URL ?? process.env.NEXT_PUBLIC_API_GATEWAY_URL;

  if (configuredUrl && configuredUrl.trim().length > 0) {
    return normalizeBaseUrl(configuredUrl);
  }

  if (process.env.NODE_ENV === "development") {
    return DEVELOPMENT_FALLBACK_URL;
  }

  return DEFAULT_INTERNAL_BASE_URL;
}

function validateSystemStatus(
  payload: unknown,
): asserts payload is SystemStatus {
  if (typeof payload !== "object" || payload === null) {
    throw new Error("System status payload was not an object");
  }

  const candidate = payload as Partial<SystemStatus>;
  if (typeof candidate.status !== "string") {
    throw new Error("System status payload is missing the status field");
  }

  if (!Array.isArray(candidate.services)) {
    throw new Error("System status payload is missing the services array");
  }

  if (typeof candidate.timestamp !== "string") {
    throw new Error("System status payload is missing the timestamp field");
  }
}

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const baseUrl = resolveBaseUrl();
  const endpoint = `${baseUrl}/api/v1/system-status`;

  const response = await fetch(endpoint, {
    cache: "no-store",
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(
      `API gateway responded with ${response.status} ${response.statusText}`,
    );
  }

  const payload = (await response.json()) as unknown;
  validateSystemStatus(payload);

  return payload;
}
