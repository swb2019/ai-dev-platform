import type { Route } from "next";
import Link from "next/link";

export default function Home(): JSX.Element {
  return (
    <div className="flex flex-1 flex-col items-center justify-center px-4 py-8">
      <div className="mx-auto max-w-4xl text-center">
        <h1 className="mb-6 text-4xl font-bold tracking-tight text-foreground sm:text-6xl">
          AI Dev Platform
        </h1>
        <p className="mb-8 text-lg leading-8 text-muted-foreground">
          A secure, AI-powered development platform built with modern tools and
          security-first architecture.
        </p>
        <div className="flex items-center justify-center gap-4">
          <Link
            href={"/docs" as Route}
            className="rounded-md bg-primary px-6 py-3 text-sm font-semibold text-primary-foreground shadow-sm hover:bg-primary/90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary"
          >
            Get Started
          </Link>
          <Link
            href={"/about" as Route}
            className="rounded-md border border-border px-6 py-3 text-sm font-semibold text-foreground shadow-sm hover:bg-accent hover:text-accent-foreground focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent"
          >
            Learn More
          </Link>
        </div>
      </div>

      <div className="mt-16 grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3">
        <div className="rounded-lg border border-border bg-card p-6 text-card-foreground shadow-sm">
          <h3 className="mb-2 text-lg font-semibold">Security First</h3>
          <p className="text-sm text-muted-foreground">
            Built-in security scanning with Gitleaks, Semgrep, and comprehensive
            linting rules.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-6 text-card-foreground shadow-sm">
          <h3 className="mb-2 text-lg font-semibold">AI-Powered</h3>
          <p className="text-sm text-muted-foreground">
            Integrated AI development tools including Claude Code and GitHub
            Copilot.
          </p>
        </div>
        <div className="rounded-lg border border-border bg-card p-6 text-card-foreground shadow-sm">
          <h3 className="mb-2 text-lg font-semibold">Modern Stack</h3>
          <p className="text-sm text-muted-foreground">
            Next.js 14, TypeScript, Tailwind CSS, and Turbo monorepo
            architecture.
          </p>
        </div>
      </div>
    </div>
  );
}
