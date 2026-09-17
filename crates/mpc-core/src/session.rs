//! Protocol sessions and round state.

/// A session identifier. Reused values are rejected, which blocks replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub [u8; 32]);

/// A protocol round. Messages that arrive out of order discard the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Round {
    /// The session has started but no messages have been exchanged.
    Init,
    /// Round `n` is in progress.
    Round(u8),
    /// The protocol finished.
    Done,
}

impl Round {
    /// The round that should come next.
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
