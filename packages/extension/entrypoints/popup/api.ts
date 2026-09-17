/** Wraps requests to the background worker. The UI never handles secrets directly. */
import type { Request, Response } from '../../src/messages';

export async function send<T>(request: Request): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  if (!response.ok) throw new Error(response.error);
  return response.value;
}
