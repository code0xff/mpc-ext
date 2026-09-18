/**
 * The approval queue.
 *
 * A page request that needs the user's consent parks here while the approval window is open.
 * Nothing is signed until the user says yes, and a closed window counts as a refusal — never as
 * a silent success (`docs/web-api.md`).
 */
import { RPC_ERROR } from './rpc';

/** What the user is being asked to approve. */
export type ApprovalKind =
  { kind: 'connect' } | { kind: 'personalSign'; messageHex: string; digestHex: string };

export interface Approval {
  id: string;
  /** The origin as the browser reported it, never as the page claimed it. */
  origin: string;
  request: ApprovalKind;
}

interface Waiting extends Approval {
  settle: (approved: boolean) => void;
}

const queue = new Map<string, Waiting>();

/** Everything currently awaiting the user, oldest first. */
export function pending(): Approval[] {
  return [...queue.values()].map(({ id, origin, request }) => ({ id, origin, request }));
}

/**
 * Parks a request and resolves once the user decides.
 *
 * Declining rejects with the EIP-1193 user-rejection code, so a dApp's existing error handling
 * sees what it expects.
 */
export function ask(id: string, origin: string, request: ApprovalKind): Promise<void> {
  return new Promise((resolve, reject) => {
    queue.set(id, {
      id,
      origin,
      request,
      settle: (approved) => {
        queue.delete(id);
        if (approved) {
          resolve();
        } else {
          reject(
            Object.assign(new Error('The user rejected the request.'), {
              code: RPC_ERROR.userRejected,
            }),
          );
        }
      },
    });
  });
}

/** Records the user's decision. Returns false if the request had already gone away. */
export function decide(id: string, approved: boolean): boolean {
  const waiting = queue.get(id);
  if (!waiting) return false;
  waiting.settle(approved);
  return true;
}

/**
 * Rejects everything still waiting.
 *
 * Called when the approval window closes and when the wallet locks: an unanswered request has to
 * fail closed.
 */
export function rejectAll(): void {
  for (const waiting of [...queue.values()]) {
    waiting.settle(false);
  }
}
