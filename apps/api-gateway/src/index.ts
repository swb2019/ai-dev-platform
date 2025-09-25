import type { Server } from "http";

import { createApp } from "./app";

const DEFAULT_PORT = 4000;

export function startServer(port: number = DEFAULT_PORT): Server {
  const app = createApp();
  const resolvedPort = Number.isNaN(Number(port)) ? DEFAULT_PORT : Number(port);

  return app.listen(resolvedPort, () => {
    if (process.env.NODE_ENV !== "test") {
      // eslint-disable-next-line no-console
      console.info(`api-gateway listening on port ${resolvedPort}`);
    }
  });
}

if (require.main === module) {
  const portFromEnv = process.env.PORT
    ? Number(process.env.PORT)
    : DEFAULT_PORT;
  startServer(portFromEnv);
}
