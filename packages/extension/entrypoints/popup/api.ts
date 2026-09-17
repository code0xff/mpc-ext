/** background로 보내는 요청 래퍼. UI는 비밀 값을 직접 다루지 않는다. */
import type { Request, Response } from '../../src/messages';

export async function send<T>(request: Request): Promise<T> {
  const response = (await chrome.runtime.sendMessage(request)) as Response<T>;
  if (!response.ok) throw new Error(response.error);
  return response.value;
}
