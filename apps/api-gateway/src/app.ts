import cors, { type CorsOptions } from "cors";
import express, { json, type RequestHandler, urlencoded } from "express";
import helmet from "helmet";

import { systemStatusRouter } from "./routes/system-status";

function buildCorsOrigins(): CorsOptions["origin"] {
  const configuredOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!configuredOrigins) {
    return true;
  }

  const origins = configuredOrigins
    .split(",")
    .map((origin) => origin.trim())
    .filter((origin) => origin.length > 0);

  return origins.length > 0 ? origins : true;
}

export function createApp(): express.Express {
  const app = express();

  app.disable("x-powered-by");

  app.use(
    helmet({
      contentSecurityPolicy: false,
      crossOriginEmbedderPolicy: false,
    }),
  );
  app.use(
    cors({
      origin: buildCorsOrigins(),
      methods: ["GET"],
    }),
  );
  app.use(json());
  app.use(urlencoded({ extended: false }));

  const healthHandler: RequestHandler = (_req, res) => {
    res.status(200).json({ status: "ok" });
  };
  app.get("/healthz", healthHandler);

  app.use("/api/v1", systemStatusRouter);

  const notFoundHandler: RequestHandler = (req, res) => {
    res.status(404).json({ error: "Not Found", path: req.path });
  };

  app.use(notFoundHandler);

  return app;
}

export type { Request, Response } from "express";
