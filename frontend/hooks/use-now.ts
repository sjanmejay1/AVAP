"use client";

import { useEffect, useState } from "react";

/**
 * The current time, re-rendered every `intervalMs` while `active`. Drives
 * the live elapsed clock on a running scan without any extra requests.
 */
export function useNow(active: boolean, intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(timer);
  }, [active, intervalMs]);

  return now;
}
