'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { CheckCircle2, Loader2, LogOut } from 'lucide-react';

import { Button } from '@/components/ui/button';

interface PlanModel {
  id: string;
  name: string;
}

interface PlanStatus {
  available: boolean;
  connected: boolean;
  email?: string;
  reason?: string;
  models: PlanModel[];
}

interface ChatGPTPlanSettingsProps {
  onConnected: (models: string[]) => Promise<void>;
  onDisconnected: () => Promise<void>;
}

export function ChatGPTPlanSettings({ onConnected, onDisconnected }: ChatGPTPlanSettingsProps) {
  const [status, setStatus] = useState<PlanStatus | null>(null);
  const [busy, setBusy] = useState<'connect' | 'disconnect' | null>(null);
  const [message, setMessage] = useState('');
  const synced = useRef(false);

  const load = useCallback(async () => {
    const response = await fetch('/api/chatgpt-plan', { cache: 'no-store' });
    const next = (await response.json()) as PlanStatus;
    setStatus(next);
    if (next.connected && next.models.length && !synced.current) {
      synced.current = true;
      await onConnected(next.models.map((model) => model.id));
    }
    return next;
  }, [onConnected]);

  useEffect(() => {
    void load().catch(() => setMessage('Could not read ChatGPT connection status.'));
  }, [load]);

  const connect = async () => {
    setBusy('connect');
    setMessage('');
    synced.current = false;
    try {
      const response = await fetch('/api/chatgpt-plan/start', { method: 'POST' });
      const data = (await response.json()) as { authorizationUrl?: string; error?: string };
      if (!response.ok || !data.authorizationUrl) {
        throw new Error(data.error || 'ChatGPT sign-in could not start.');
      }
      const popup = window.open(
        data.authorizationUrl,
        'openmaic-chatgpt-signin',
        'popup,width=620,height=760',
      );
      if (!popup) {
        throw new Error('The browser blocked the ChatGPT sign-in window.');
      }

      const deadline = Date.now() + 10 * 60 * 1000;
      while (Date.now() < deadline && !popup.closed) {
        await new Promise((resolve) => window.setTimeout(resolve, 1500));
        const next = await load();
        if (next.connected) {
          popup.close();
          setMessage('Connected. OpenMAIC will use your ChatGPT plan for this provider.');
          return;
        }
      }
      const next = await load();
      if (!next.connected) setMessage('ChatGPT sign-in was not completed.');
    } catch (error) {
      setMessage(error instanceof Error ? error.message : 'ChatGPT sign-in failed.');
    } finally {
      setBusy(null);
    }
  };

  const disconnect = async () => {
    setBusy('disconnect');
    setMessage('');
    try {
      await fetch('/api/chatgpt-plan', { method: 'DELETE' });
      synced.current = false;
      await onDisconnected();
      await load();
      setMessage('Disconnected from ChatGPT.');
    } catch {
      setMessage('Could not disconnect ChatGPT.');
    } finally {
      setBusy(null);
    }
  };

  if (!status) {
    return (
      <div className="flex items-center gap-2 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" />
        Checking ChatGPT…
      </div>
    );
  }

  if (!status.available) {
    return (
      <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-sm text-amber-800 dark:border-amber-800 dark:bg-amber-950/30 dark:text-amber-300">
        <p className="font-medium">ChatGPT plan sign-in is disabled.</p>
        <p className="mt-1 text-xs">{status.reason}</p>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-lg border border-border/60 p-4">
      {status.connected ? (
        <>
          <div className="flex items-center gap-2">
            <CheckCircle2 className="size-4 text-emerald-600" />
            <div>
              <p className="text-sm font-medium">ChatGPT plan connected</p>
              {status.email && <p className="text-xs text-muted-foreground">{status.email}</p>}
            </div>
          </div>
          <p className="text-xs text-muted-foreground">
            {status.models.length
              ? status.models.length + ' model(s) available for this account.'
              : 'Connected. Model discovery will retry automatically.'}
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void disconnect()}
            disabled={busy !== null}
            className="gap-1.5"
          >
            {busy === 'disconnect' ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <LogOut className="size-3.5" />
            )}
            Disconnect
          </Button>
        </>
      ) : (
        <>
          <div>
            <p className="text-sm font-medium">Use your ChatGPT Plus / Pro plan</p>
            <p className="mt-1 text-xs text-muted-foreground">
              Sign in with ChatGPT. No OpenAI API key is needed. Usage counts against your ChatGPT
              plan limits.
            </p>
          </div>
          <Button
            type="button"
            size="sm"
            onClick={() => void connect()}
            disabled={busy !== null}
          >
            {busy === 'connect' && <Loader2 className="mr-1.5 size-3.5 animate-spin" />}
            Continue with ChatGPT
          </Button>
        </>
      )}
      {message && <p className="text-xs text-muted-foreground">{message}</p>}
    </div>
  );
}
