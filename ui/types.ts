// Shapes returned by the backend under /api/services/remshel/.

export interface ShellStatus {
  service: string;
  version: string;
  user: string;
  /** True when the user is shell-entitled (login shell != nologin) — the single source of truth. */
  enabled: boolean;
  /** The login shell that would run (e.g. /bin/bash), or the disabling shell (nologin). */
  shell: string;
}
