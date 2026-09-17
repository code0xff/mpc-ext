//! `mpc-core`의 wasm 바인딩.
//!
//! 이 계층은 타입 변환만 담당한다. 프로토콜 로직을 여기에 두지 않는다.
//! 비밀 값을 JS 쪽으로 넘기지 않으며, 셰어는 wasm 메모리 안에 머문다.

use mpc_core::{THRESHOLD, TOTAL_PARTIES};
use wasm_bindgen::prelude::wasm_bindgen;

/// 이 빌드가 사용하는 임계 설정을 `"2-of-3"` 형태로 반환한다.
///
/// 확장 UI가 wasm 로딩 성공 여부를 확인하는 헬스체크로도 쓴다.
#[wasm_bindgen]
pub fn threshold_config() -> String {
    format!("{THRESHOLD}-of-{TOTAL_PARTIES}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_two_of_three() {
        assert_eq!(threshold_config(), "2-of-3");
    }
}
