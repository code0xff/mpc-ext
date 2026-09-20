/**
 * The reshare orchestration, with wasm and the server replaced by fakes. The protocol itself is
 * tested in `mpc-core` and against the real server; this checks the glue: which parties run,
 * that a changed public key is refused, and that a failure tells the server to let go.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

const PUBLIC_KEY = new Uint8Array(33).fill(0x02);
const PUBLIC_KEY_HEX = '02'.repeat(33);

class FakeSession {
  finished = false;
  outgoing = '[]';
  constructor(
    readonly share: Uint8Array,
    readonly public_key: Uint8Array,
  ) {}
  advance(): void {
    this.finished = true;
  }
}

const started: string[] = [];

vi.mock('./wasm', () => ({
  DkgSession: {
    reshareJoiner: (party: number) => {
      started.push(`joiner:${party}`);
      return new FakeSession(new Uint8Array([1]), PUBLIC_KEY);
    },
    reshareSurvivor: (party: number, _id: Uint8Array, share: Uint8Array) => {
      started.push(`survivor:${party}:${share[0]}`);
      return new FakeSession(new Uint8Array([2]), PUBLIC_KEY);
    },
  },
  SignSession: class {},
}));

const server = {
  startReshare: vi.fn(),
  advanceReshare: vi.fn(),
  abortReshare: vi.fn(),
};
vi.mock('./serverClient', () => server);

const { runReshare } = await import('./protocolRunner');

const ID = new Uint8Array(32).fill(0xe1);
const OLD_B = new Uint8Array([9]);

describe('runReshare', () => {
  beforeEach(() => {
    started.length = 0;
    server.startReshare.mockReset().mockResolvedValue([]);
    server.advanceReshare.mockReset();
    server.abortReshare.mockReset().mockResolvedValue(undefined);
  });

  it('plays the joiner as A and the survivor as B, and returns both new shares', async () => {
    server.advanceReshare.mockResolvedValue({ state: 'staged', public_key: PUBLIC_KEY_HEX });

    const outcome = await runReshare('http://s', 'wallet', ID, OLD_B, PUBLIC_KEY);

    expect(started).toEqual(['joiner:0', 'survivor:1:9']);
    expect(outcome.extensionShare).toEqual(new Uint8Array([1]));
    expect(outcome.recoveryShare).toEqual(new Uint8Array([2]));
    expect(outcome.publicKeyHex).toBe(PUBLIC_KEY_HEX);
    expect(server.abortReshare).not.toHaveBeenCalled();
  });

  it('refuses a reshare the server says would change the address, and aborts it', async () => {
    server.advanceReshare.mockResolvedValue({ state: 'staged', public_key: '03'.repeat(33) });

    await expect(runReshare('http://s', 'wallet', ID, OLD_B, PUBLIC_KEY)).rejects.toThrow(
      /changed the wallet address/,
    );
    expect(server.abortReshare).toHaveBeenCalledTimes(1);
  });

  it('tells the server to let go when a round fails, and keeps the real error', async () => {
    server.advanceReshare.mockRejectedValue(new Error('round failed'));

    await expect(runReshare('http://s', 'wallet', ID, OLD_B, PUBLIC_KEY)).rejects.toThrow(
      'round failed',
    );
    expect(server.abortReshare).toHaveBeenCalledTimes(1);
  });

  it('does not let a failing abort hide the original error', async () => {
    server.advanceReshare.mockRejectedValue(new Error('round failed'));
    server.abortReshare.mockRejectedValue(new Error('server down'));

    await expect(runReshare('http://s', 'wallet', ID, OLD_B, PUBLIC_KEY)).rejects.toThrow(
      'round failed',
    );
  });

  it('gives up if the server never stages the share', async () => {
    server.advanceReshare.mockResolvedValue({ state: 'inProgress', envelopes: [] });

    await expect(runReshare('http://s', 'wallet', ID, OLD_B, PUBLIC_KEY)).rejects.toThrow(
      /expected number of rounds/,
    );
    expect(server.abortReshare).toHaveBeenCalledTimes(1);
  });
});
