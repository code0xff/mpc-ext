/**
 * 웹페이지가 mpc-ext 확장을 발견하기 위한 얇은 래퍼.
 *
 * 이 SDK는 비밀에 접근하지 않는다. 확장이 서명 결과만 돌려주며, 모든 서명·연결
 * 요청은 사용자 승인을 거친다 (`docs/web-api.md`).
 *
 * 커스텀 API를 만들지 않고 EIP-6963 / EIP-1193 표준을 따른다.
 */

/** EIP-6963이 정의하는 지갑 식별 정보. */
export interface ProviderInfo {
  /** 지갑 인스턴스의 UUID. */
  uuid: string;
  /** 사람이 읽는 이름. */
  name: string;
  /** data URI 아이콘. */
  icon: string;
  /** 역-DNS 식별자. */
  rdns: string;
}

/** EIP-1193 provider 중 이 SDK가 사용하는 최소 표면. */
export interface Eip1193Provider {
  request(args: { method: string; params?: unknown[] }): Promise<unknown>;
}

/** EIP-6963 announce 이벤트가 싣고 오는 값. */
export interface ProviderDetail {
  info: ProviderInfo;
  provider: Eip1193Provider;
}

/** 이 확장의 EIP-6963 식별자. */
export const MPC_EXT_RDNS = 'labs.dsrv.mpc-ext';

/**
 * EIP-6963으로 announce되는 지갑을 수집한다.
 *
 * @param timeoutMs announce를 기다리는 시간.
 * @returns 발견된 provider 목록. 확장이 없으면 빈 배열.
 */
export function discoverProviders(timeoutMs = 300): Promise<ProviderDetail[]> {
  const found = new Map<string, ProviderDetail>();

  const onAnnounce = (event: Event): void => {
    const detail = (event as CustomEvent<ProviderDetail>).detail;
    if (detail?.info?.uuid) {
      found.set(detail.info.uuid, detail);
    }
  };

  window.addEventListener('eip6963:announceProvider', onAnnounce);
  window.dispatchEvent(new Event('eip6963:requestProvider'));

  return new Promise((resolve) => {
    setTimeout(() => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce);
      resolve([...found.values()]);
    }, timeoutMs);
  });
}

/**
 * mpc-ext 확장만 골라낸다.
 *
 * @returns 확장이 설치되어 있지 않으면 `undefined`.
 */
export async function findMpcExt(timeoutMs?: number): Promise<ProviderDetail | undefined> {
  const providers = await discoverProviders(timeoutMs);
  return providers.find((p) => p.info.rdns === MPC_EXT_RDNS);
}
