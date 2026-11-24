import Link from "next/link";

import { Wordmark } from "@/components/shared/wordmark";

/**
 * Two destinations only (targets and profile), so no sidebar: a slim top
 * bar, then one left-aligned content column.
 */
export function AppShell({
  accountMenu,
  children,
}: {
  /** Rendered at the right of the top bar; supplied by the signed-in layout. */
  accountMenu: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="flex min-h-screen flex-col">
      <a
        href="#main"
        className="sr-only z-50 rounded-md bg-primary px-3 py-2 text-sm text-primary-foreground focus:not-sr-only focus:fixed focus:top-2 focus:left-2"
      >
        Skip to content
      </a>
      <header className="sticky top-0 z-40 border-b border-border bg-background">
        <div className="mx-auto flex h-14 w-full max-w-[1200px] items-center justify-between gap-4 px-4 sm:px-6">
          <div className="flex items-center gap-6">
            <Link href="/targets" aria-label="AVAP targets" className="rounded-sm">
              <Wordmark />
            </Link>
            <nav aria-label="Main">
              <Link
                href="/targets"
                className="rounded-sm text-sm font-medium text-muted-foreground hover:text-foreground"
              >
                Targets
              </Link>
            </nav>
          </div>
          {accountMenu}
        </div>
      </header>
      <main
        id="main"
        tabIndex={-1}
        className="mx-auto w-full max-w-[1200px] flex-1 px-4 py-8 outline-none sm:px-6 lg:py-10"
      >
        {children}
      </main>
    </div>
  );
}
