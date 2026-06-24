/// Pending RX operations for a single connection, stored as a u8 bitmask.
///
/// Dequeued in fixed priority order (lowest bit = highest priority).
/// Each operation type can only be pending once at a time.
#[derive(Debug, Clone, Copy, Default)]
pub struct RxOps(u8);

impl RxOps {
    // Priority order (lowest bit wins): Request > Rw > Response > CreditUpdate > Reset > CreditRequest
    pub const REQUEST: u8 = 0x01;
    pub const RW: u8 = 0x02;
    pub const RESPONSE: u8 = 0x04;
    pub const CREDIT_UPDATE: u8 = 0x08;
    pub const RESET: u8 = 0x10;
    pub const CREDIT_REQUEST: u8 = 0x20;

    /// Returns true if any operation is pending.
    pub fn pending(&self) -> bool {
        self.0 != 0
    }

    /// Enqueues an operation (sets bit).
    pub fn enqueue(&mut self, op: u8) {
        self.0 |= op;
    }

    /// Dequeues the highest-priority pending operation (clears bit).
    /// Returns the operation bitmask, or 0 if nothing pending.
    pub fn dequeue(&mut self) -> u8 {
        if self.0 == 0 {
            return 0;
        }
        // Lowest set bit = highest priority.
        let op = self.0 & self.0.wrapping_neg();
        self.0 &= !op;
        op
    }

    /// Peeks at the highest-priority pending operation without removing it.
    pub fn peek(&self) -> u8 {
        if self.0 == 0 {
            return 0;
        }
        self.0 & self.0.wrapping_neg()
    }
}
