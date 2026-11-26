"use client";

import { PageHeader } from "@/components/shared/page-header";
import { useAuth } from "@/features/auth/hooks/use-auth";
import { OpenRouterKeySection } from "@/features/profile/components/openrouter-key-section";
import { PasswordSection } from "@/features/profile/components/password-section";
import { formatDateTime } from "@/utils/format";

export function ProfileView() {
  const { user } = useAuth();

  return (
    <div className="flex flex-col">
      <PageHeader title="Profile" />
      <div className="flex flex-col divide-y divide-border">
        <section aria-labelledby="account-heading" className="flex flex-col gap-4 pb-10">
          <h2 id="account-heading" className="text-h3">
            Account
          </h2>
          <dl className="grid max-w-md grid-cols-[auto_minmax(0,1fr)] gap-x-6 gap-y-2 text-sm">
            <dt className="text-muted-foreground">Email</dt>
            <dd className="break-words">{user?.email}</dd>
            <dt className="text-muted-foreground">Member since</dt>
            <dd>{user ? formatDateTime(user.created_at) : "—"}</dd>
          </dl>
        </section>
        <div className="py-10">
          <OpenRouterKeySection />
        </div>
        <div className="pt-10">
          <PasswordSection />
        </div>
      </div>
    </div>
  );
}
