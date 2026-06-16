import { useState } from 'react';
import {
  Badge,
  Button,
  EmptyState,
  Panel,
  Spinner,
  Stack,
  Terminal,
  TerminalIcon,
  Text,
  useLiveQuery,
  type ServiceContextProps,
} from '@holistic/ui';
import type { ShellStatus } from './types';

// The remshel console. Whether the shell is available is read from the backend's `status`
// (which reads the user's login shell — the single source of truth). When enabled, it mounts
// the SDK Terminal, which bridges a WebSocket to a login shell running AS this user.
export function Console({ api, ui }: ServiceContextProps) {
  const status = useLiveQuery<ShellStatus>(() => api.get<ShellStatus>('status'), 15000);
  const [ended, setEnded] = useState<string | null>(null);

  if (!status.data) {
    return status.loading ? <Spinner /> : <Text color="danger">Status konnte nicht geladen werden.</Text>;
  }

  if (!status.data.enabled) {
    return (
      <Panel className="p-6">
        <EmptyState
          icon={<TerminalIcon />}
          title="Shell-Zugang ist deaktiviert"
          description="Für dein Konto ist keine Login-Shell freigegeben. Ein Administrator kann die Shell-Freigabe unter „Rechte“ aktivieren."
        />
      </Panel>
    );
  }

  return (
    <Stack gap={3}>
      <Stack direction="row" align="center" justify="between" gap={3}>
        <Stack gap={1}>
          <Stack direction="row" align="center" gap={2}>
            <Text variant="subhead" weight="semibold">
              Remote Shell
            </Text>
            <Badge variant="neutral">{status.data.user}</Badge>
            <Badge variant="neutral">{status.data.shell}</Badge>
          </Stack>
          <Text variant="footnote" color="secondary">
            Läuft mit genau deinen Rechten. Die Sitzung wird vollständig aufgezeichnet.
          </Text>
        </Stack>
        {ended && (
          <Button variant="secondary" size="sm" onClick={() => setEnded(null)}>
            Neu verbinden
          </Button>
        )}
      </Stack>

      {ended ? (
        <Panel className="p-6">
          <EmptyState icon={<TerminalIcon />} title="Sitzung beendet" description={ended} />
        </Panel>
      ) : (
        <Terminal
          url={api.url('pty')}
          height="70vh"
          onError={(m) => ui.toast({ title: 'Shell-Fehler', description: m, variant: 'error' })}
          onClose={({ code, reason }) =>
            setEnded(reason ? `Verbindung geschlossen: ${reason}` : `Die Shell wurde beendet (Code ${code}).`)
          }
        />
      )}
    </Stack>
  );
}
