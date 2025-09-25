import { Router } from "express";

const services = ["Frontend", "API Gateway", "Database (Mock)"] as const;

export const systemStatusRouter: Router = Router();

systemStatusRouter.get("/system-status", (_req, res) => {
  const responseBody = {
    status: "Operational" as const,
    services: [...services],
    timestamp: new Date().toISOString(),
  };

  res.status(200).json(responseBody);
});

type SystemStatusResponse = {
  status: "Operational";
  services: string[];
  timestamp: string;
};

export type { SystemStatusResponse };
