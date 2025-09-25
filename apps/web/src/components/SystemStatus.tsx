import type { SystemStatus } from "../lib/system-status";

type SystemStatusProps = {
  status: SystemStatus;
};

function StatusIndicator(): JSX.Element {
  return (
    <span
      aria-hidden="true"
      className="inline-flex h-2.5 w-2.5 rounded-full bg-emerald-500"
    />
  );
}

export function SystemStatusPanel({ status }: SystemStatusProps): JSX.Element {
  return (
    <div className="space-y-6 rounded-lg border border-border bg-card p-6 text-card-foreground shadow-sm">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold">Current Platform Status</h2>
          <p className="text-sm text-muted-foreground">
            Monitoring the health of critical services that power the AI Dev
            Platform.
          </p>
        </div>
        <div className="inline-flex items-center gap-2 rounded-full bg-emerald-500/10 px-4 py-1 text-sm font-medium text-emerald-500">
          <StatusIndicator />
          <span>{status.status}</span>
        </div>
      </div>

      <div className="space-y-2">
        <p className="text-sm font-medium text-muted-foreground">Services</p>
        <ul className="grid gap-2 md:grid-cols-2">
          {status.services.map((service) => (
            <li
              key={service}
              className="flex items-center gap-3 rounded-md border border-border/60 bg-muted/30 px-3 py-2 text-sm"
            >
              <StatusIndicator />
              <span>{service}</span>
            </li>
          ))}
        </ul>
      </div>

      <p className="text-xs text-muted-foreground">
        Last updated: <span className="font-medium">{status.timestamp}</span>
      </p>
    </div>
  );
}
