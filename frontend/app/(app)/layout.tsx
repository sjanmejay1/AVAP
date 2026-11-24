import { AppShell } from "@/components/shared/app-shell";
import { AccountMenu } from "@/features/auth/components/account-menu";
import { AuthGuard } from "@/features/auth/components/auth-guard";

export default function SignedInLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      <AppShell accountMenu={<AccountMenu />}>{children}</AppShell>
    </AuthGuard>
  );
}
