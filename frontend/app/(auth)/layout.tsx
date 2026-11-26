import { Wordmark } from "@/components/shared/wordmark";
import { GuestGuard } from "@/features/auth/components/guest-guard";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <GuestGuard>
      <main className="mx-auto flex min-h-screen w-full max-w-sm flex-col justify-center gap-10 px-4 py-12">
        <div className="flex flex-col gap-3">
          <Wordmark className="text-2xl" />
          <p className="text-sm text-muted-foreground">
            Scan hosts and networks you own with Nmap, see what is exposed, and get
            a risk-scored report.
          </p>
        </div>
        {children}
      </main>
    </GuestGuard>
  );
}
