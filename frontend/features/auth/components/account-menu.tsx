"use client";

import { ChevronDown, LogOut, UserRound } from "lucide-react";
import Link from "next/link";

import { ThemeMenuItems } from "@/components/shared/theme-toggle";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useAuth, useLogout } from "@/features/auth/hooks/use-auth";

export function AccountMenu() {
  const { user } = useAuth();
  const { mutate: logout, isPending } = useLogout();

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="max-w-[60vw] gap-1.5 px-2 sm:max-w-xs">
          <span className="truncate text-sm">{user?.email ?? "Account"}</span>
          <ChevronDown className="size-4 text-muted-foreground" aria-hidden="true" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <DropdownMenuLabel className="truncate">Signed in as {user?.email}</DropdownMenuLabel>
        <DropdownMenuItem asChild>
          <Link href="/profile">
            <UserRound aria-hidden="true" />
            Profile
          </Link>
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <ThemeMenuItems />
        <DropdownMenuSeparator />
        <DropdownMenuItem disabled={isPending} onSelect={() => logout()}>
          <LogOut aria-hidden="true" />
          {isPending ? "Signing out…" : "Sign out"}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
