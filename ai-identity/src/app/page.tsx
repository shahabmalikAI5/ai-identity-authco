import Link from "next/link"

export default function Home() {
  return (
    <div className="flex flex-col flex-1 items-center justify-center px-4 py-16">
      <main className="flex flex-col items-center gap-6 text-center">
        <h1 className="text-4xl font-bold tracking-tight">AuthCo</h1>
        <p className="max-w-md text-lg text-zinc-500">
          Your own identity service — and a live demo of delegated authority: an agent can act for
          you only after you approve, only on the capabilities you allow, only until it expires, and
          you can revoke it anytime.
        </p>
        <div className="flex gap-4 mt-4">
          <Link
            href="/sign-in"
            className="inline-flex h-9 items-center justify-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground hover:bg-primary/80"
          >
            Sign in
          </Link>
          <Link
            href="/sign-up"
            className="inline-flex h-9 items-center justify-center rounded-lg border px-4 text-sm font-medium hover:bg-accent"
          >
            Sign up
          </Link>
        </div>
      </main>

      <section className="mt-12 w-full max-w-lg space-y-3">
        <h2 className="text-center text-sm font-semibold text-zinc-500 uppercase tracking-wide">
          Try the on-behalf-of flow
        </h2>
        <Link
          href="/demo/agent-console"
          className="block rounded-lg border p-4 text-left transition-colors hover:bg-accent"
        >
          <p className="font-medium">Act as the agent</p>
          <p className="text-sm text-zinc-500">
            Open the agent console, request the right to act for you, and get a device code.
          </p>
        </Link>
        <div className="rounded-lg border p-4">
          <p className="font-medium">Approve as the customer</p>
          <p className="text-sm text-zinc-500">
            The approval page is reached from the agent&apos;s request link. Sign in, review the
            requested capabilities, and approve or deny.
          </p>
        </div>
      </section>
    </div>
  );
}
