import { Breadcrumbs, type Crumb } from "@/components/shared/breadcrumbs";
import { cn } from "@/lib/utils";

/**
 * Page title block. `wide` sets the title in Archivo expanded: used when the
 * title is the thing being assessed (a target), so it reads as the headline.
 */
export function PageHeader({
  title,
  description,
  actions,
  breadcrumbs,
  wide = false,
}: {
  title: string;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  breadcrumbs?: Crumb[];
  wide?: boolean;
}) {
  return (
    <div className="flex flex-col gap-3 pb-8">
      {breadcrumbs && <Breadcrumbs items={breadcrumbs} />}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="min-w-0">
          <h1
            className={cn(
              "text-h1 break-words text-foreground sm:text-display",
              wide && "type-wide"
            )}
          >
            {title}
          </h1>
          {description && (
            <div className="mt-2 text-sm text-muted-foreground">{description}</div>
          )}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}
