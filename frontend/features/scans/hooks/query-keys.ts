/** Deterministic query key factory for the Scans feature. */
export const scanKeys = {
  all: ["scans"] as const,
  lists: () => [...scanKeys.all, "list"] as const,
  list: (params: { skip: number; limit: number; target_id?: string }) =>
    [...scanKeys.lists(), params] as const,
  details: () => [...scanKeys.all, "detail"] as const,
  detail: (id: string) => [...scanKeys.details(), id] as const,
  status: (id: string) => [...scanKeys.all, "status", id] as const,
  hosts: (id: string) => [...scanKeys.all, "hosts", id] as const,
};
