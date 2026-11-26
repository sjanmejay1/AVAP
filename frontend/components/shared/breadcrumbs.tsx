import { ChevronRight } from "lucide-react";
import Link from "next/link";

export interface Crumb {
  label: string;
  href?: string;
}

/**
 * The page's place in Targets → target → scan. The last crumb is the
 * current page and is not a link. On small screens only the parent link is
 * shown, as a back link.
 */
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  const parent = [...items].reverse().find((item) => item.href);

  return (
    <nav aria-label="Breadcrumb" className="text-sm text-muted-foreground">
      {parent?.href && (
        <Link href={parent.href} className="hover:text-foreground sm:hidden">
          Back to {parent.label}
        </Link>
      )}
      <ol className="hidden flex-wrap items-center gap-1.5 sm:flex">
        {items.map((item, index) => (
          <li key={`${item.label}-${index}`} className="flex min-w-0 items-center gap-1.5">
            {index > 0 && <ChevronRight className="size-3.5 shrink-0" aria-hidden="true" />}
            {item.href ? (
              <Link href={item.href} className="truncate hover:text-foreground">
                {item.label}
              </Link>
            ) : (
              <span aria-current="page" className="truncate text-foreground">
                {item.label}
              </span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
