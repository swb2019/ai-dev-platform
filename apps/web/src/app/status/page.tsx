import type { Metadata } from "next";

import { SystemStatusPanel } from "../../components/SystemStatus";
import { fetchSystemStatus, type SystemStatus } from "../../lib/system-status";

export const metadata: Metadata = {
  title: "System Status | AI Dev Platform",
  description:
    "Live operational status for the AI Dev Platform services, including the web application and API gateway.",
};

export const revalidate = 0;

export default async function StatusPage(): Promise<JSX.Element> {
  let status: SystemStatus | null = null;
  let errorMessage: string | null = null;

  try {
    status = await fetchSystemStatus();
  } catch (error) {
    errorMessage =
      error instanceof Error
        ? error.message
        : "Unable to retrieve the current system status.";
  }

  return (
    <div className="mx-auto flex min-h-[calc(100vh-4rem)] max-w-5xl flex-col gap-8 px-4 py-10">
      <header className="space-y-3">
        <h1 className="text-3xl font-bold tracking-tight text-foreground sm:text-4xl">
          Platform Status
        </h1>
        <p className="max-w-3xl text-base text-muted-foreground">
          Real-time visibility into the services that power the AI Dev Platform.
          The status page queries the internal API gateway via the cluster
          network to provide an up-to-date heartbeat.
        </p>
      </header>

      {status ? (
        <SystemStatusPanel status={status} />
      ) : (
        <div className="rounded-lg border border-destructive/20 bg-destructive/10 p-6 text-destructive-foreground">
          <h2 className="text-lg font-semibold">
            Unable to load system status
          </h2>
          <p className="mt-2 text-sm">
            {errorMessage ??
              "An unexpected error occurred while requesting the system status."}
          </p>
          <p className="mt-4 text-xs text-destructive-foreground/70">
            The platform will continue to retry, or you can refresh the page to
            attempt the request again.
          </p>
        </div>
      )}
    </div>
  );
}
