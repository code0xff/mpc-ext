//! 프로토콜 세션과 라운드 상태.

/// 세션 식별자. 재사용된 값은 거부한다 (리플레이 방지).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub [u8; 32]);

/// 프로토콜 라운드. 순서를 어긴 메시지는 세션을 폐기한다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Round {
    /// 세션 개시, 아직 메시지를 주고받지 않았다.
    Init,
    /// n번째 라운드 진행 중.
    Round(u8),
    /// 프로토콜 완료.
    Done,
}

impl Round {
    /// 다음에 와야 할 라운드.
    pub fn next(self) -> Self {
        match self {
            Round::Init => Round::Round(1),
            Round::Round(n) => Round::Round(n.saturating_add(1)),
            Round::Done => Round::Done,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounds_advance_in_order() {
        assert_eq!(Round::Init.next(), Round::Round(1));
        assert_eq!(Round::Round(1).next(), Round::Round(2));
        assert_eq!(Round::Done.next(), Round::Done);
    }
}
