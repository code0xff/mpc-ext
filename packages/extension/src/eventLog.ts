/**
 * A small local log of sensitive events, kept so the user can see that an export happened
 * (`docs/export.md`). It records what and when — never key material.
 */
const STORAGE_KEY = 'eventLog';
const MAX_ENTRIES = 100;

export type EventType = 'privateKeyExported';

export interface LogEntry {
  at: string;
  type: EventType;
}

export async function record(type: EventType): Promise<void> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  const entries = (stored[STORAGE_KEY] as LogEntry[] | undefined) ?? [];
  entries.push({ at: new Date().toISOString(), type });
  await chrome.storage.local.set({ [STORAGE_KEY]: entries.slice(-MAX_ENTRIES) });
}

export async function read(): Promise<LogEntry[]> {
  const stored = await chrome.storage.local.get(STORAGE_KEY);
  return (stored[STORAGE_KEY] as LogEntry[] | undefined) ?? [];
}
