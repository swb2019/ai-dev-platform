import request from "supertest";

import { createApp } from "../app";
import type { SystemStatusResponse } from "../routes/system-status";

describe("api-gateway routes", () => {
  const app = createApp();

  it("responds to health checks", async () => {
    const response = await request(app).get("/healthz");

    expect(response.status).toBe(200);
    expect(response.body).toEqual({ status: "ok" });
  });

  it("returns the mock system status payload", async () => {
    const response = await request(app).get("/api/v1/system-status");

    expect(response.status).toBe(200);

    const payload = response.body as SystemStatusResponse;
    expect(payload.status).toBe("Operational");
    expect(payload.services).toEqual([
      "Frontend",
      "API Gateway",
      "Database (Mock)",
    ]);
    expect(() => new Date(payload.timestamp)).not.toThrow();
    expect(new Date(payload.timestamp).toISOString()).toBe(payload.timestamp);
  });
});
