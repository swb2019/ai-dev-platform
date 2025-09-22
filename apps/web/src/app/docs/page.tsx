export default function DocsPage(): JSX.Element {
  return (
    <section className="mx-auto flex min-h-[60vh] max-w-3xl flex-col gap-4 px-4 py-12">
      <h1 className="text-3xl font-bold tracking-tight text-foreground">
        Documentation
      </h1>
      <p className="text-base text-muted-foreground">
        Additional documentation will live here. For now, this placeholder route
        satisfies typed routing requirements and confirms the navigation
        structure works end-to-end.
      </p>
    </section>
  );
}
