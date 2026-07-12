//! Replay protection.
//!
//! Stops an attacker from recording a valid packet and replaying it later. Encrypted
//! packets carry 64-bit sequence numbers that increase with each packet sent. The
//! sequence number doubles as the encryption nonce, so it cannot be modified without
//! failing the signature check. The receiver tracks recently received sequence numbers
//! in a sliding window and rejects duplicates and stale packets.

pub(crate) const REPLAY_PROTECTION_BUFFER_SIZE: usize = 256;

const EMPTY: u64 = u64::MAX;

pub(crate) struct ReplayProtection {
    most_recent_sequence: u64,
    received_packet: [u64; REPLAY_PROTECTION_BUFFER_SIZE],
}

impl ReplayProtection {
    pub fn new() -> Self {
        Self { most_recent_sequence: 0, received_packet: [EMPTY; REPLAY_PROTECTION_BUFFER_SIZE] }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn already_received(&self, sequence: u64) -> bool {
        // written subtraction-side so it cannot overflow: "sequence + BUFFER_SIZE <=
        // most_recent" wraps for sequence values near u64::MAX and falsely rejects
        // them as replays (and panics in debug builds)
        if self.most_recent_sequence >= REPLAY_PROTECTION_BUFFER_SIZE as u64
            && sequence <= self.most_recent_sequence - REPLAY_PROTECTION_BUFFER_SIZE as u64
        {
            return true;
        }

        let index = (sequence % REPLAY_PROTECTION_BUFFER_SIZE as u64) as usize;

        self.received_packet[index] != EMPTY && self.received_packet[index] >= sequence
    }

    /// Marks the sequence number as received. Call only after the packet decrypts
    /// successfully, otherwise an attacker could poison the window with forged headers.
    pub fn advance_sequence(&mut self, sequence: u64) {
        if sequence > self.most_recent_sequence {
            self.most_recent_sequence = sequence;
        }

        let index = (sequence % REPLAY_PROTECTION_BUFFER_SIZE as u64) as usize;

        self.received_packet[index] = sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIZE: u64 = REPLAY_PROTECTION_BUFFER_SIZE as u64;

    #[test]
    fn new_packets_accepted_and_replays_rejected() {
        let mut replay_protection = ReplayProtection::new();

        for sequence in 0..SIZE * 2 {
            assert!(!replay_protection.already_received(sequence));
            replay_protection.advance_sequence(sequence);
        }

        // everything received so far is a replay
        for sequence in SIZE..SIZE * 2 {
            assert!(replay_protection.already_received(sequence));
        }

        // packets older than the window are rejected
        assert!(replay_protection.already_received(0));
        assert!(replay_protection.already_received(SIZE - 1));

        // the next new packet is accepted
        assert!(!replay_protection.already_received(SIZE * 2));
    }

    #[test]
    fn out_of_order_within_window_accepted_once() {
        let mut replay_protection = ReplayProtection::new();

        replay_protection.advance_sequence(100);

        assert!(!replay_protection.already_received(99));
        replay_protection.advance_sequence(99);
        assert!(replay_protection.already_received(99));
        assert!(replay_protection.already_received(100));
    }

    #[test]
    fn sequences_near_u64_max_are_not_falsely_rejected() {
        // regression test for the integer overflow in the reference implementation:
        // the addition-side already-received test wrapped for sequences within
        // BUFFER_SIZE of u64::MAX
        let mut replay_protection = ReplayProtection::new();

        let sequence = u64::MAX - 10;
        assert!(!replay_protection.already_received(sequence));
        replay_protection.advance_sequence(sequence);

        assert!(!replay_protection.already_received(sequence + 1));
        assert!(replay_protection.already_received(sequence));
    }
}
