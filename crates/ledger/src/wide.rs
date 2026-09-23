//! A fixed-width 256-bit signed integer for the read model's read-time
//! conversion (T76, M-50 / L-79).
//!
//! The read model accumulates each `(account, currency)` balance as exact
//! per-scale `i128` partials ([`crate::read_model`]). Turning those into one
//! reported `Decimal` needs the exact total at a common scale of 28: a partial
//! can be as large as `2^127` and `10^28 ≈ 2^93`, so the total needs about 225
//! bits. That is what this type is for, and all it does: add, negate, multiply
//! by a power of ten, and divide by a power of ten either exactly or rounding
//! half to even. Every operation that can overflow is checked.
//!
//! Sign-magnitude, four little-endian `u64` limbs. Zero is never negative, so
//! the derived `PartialEq` is value equality.
//!
//! In-crate rather than a dependency: it needs five operations, it sits on the
//! path every balance goes through, and `tests/exact_balances.rs` checks it
//! against an independent base-10^9 oracle.

use std::cmp::Ordering;

/// `10^19`, the largest power of ten a `u64` holds.
const TEN_POW_19: u64 = 10_000_000_000_000_000_000;

/// A signed 256-bit integer (sign and magnitude).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct I256 {
    negative: bool,
    /// The magnitude, least significant limb first.
    limbs: [u64; 4],
}

impl I256 {
    /// Zero.
    pub const ZERO: I256 = I256 {
        negative: false,
        limbs: [0; 4],
    };

    /// The value of `value`.
    pub fn from_i128(value: i128) -> I256 {
        let magnitude = value.unsigned_abs();
        I256 {
            negative: value < 0,
            limbs: [magnitude as u64, (magnitude >> 64) as u64, 0, 0],
        }
    }

    /// Whether this is zero.
    pub fn is_zero(&self) -> bool {
        self.limbs == [0; 4]
    }

    /// Whether this is below zero.
    pub fn is_negative(&self) -> bool {
        self.negative
    }

    /// `-self`. Never overflows: the magnitude is unchanged.
    pub fn negated(self) -> I256 {
        I256::with_sign(!self.negative, self.limbs)
    }

    /// `self + other`, or `None` when the magnitude passes `2^256 − 1`.
    pub fn checked_add(self, other: I256) -> Option<I256> {
        if self.negative == other.negative {
            return Some(I256::with_sign(
                self.negative,
                add_magnitudes(&self.limbs, &other.limbs)?,
            ));
        }
        Some(match compare_magnitudes(&self.limbs, &other.limbs) {
            Ordering::Less => I256::with_sign(
                other.negative,
                subtract_magnitudes(&other.limbs, &self.limbs),
            ),
            _ => I256::with_sign(
                self.negative,
                subtract_magnitudes(&self.limbs, &other.limbs),
            ),
        })
    }

    /// `self × 10^exponent`, or `None` on overflow.
    pub fn checked_mul_pow10(self, mut exponent: u32) -> Option<I256> {
        let mut limbs = self.limbs;
        while exponent > 0 {
            let step = exponent.min(19);
            limbs = multiply_small(&limbs, 10u64.pow(step))?;
            exponent -= step;
        }
        Some(I256::with_sign(self.negative, limbs))
    }

    /// `self / 10^exponent` when that division leaves no remainder.
    pub fn div_pow10_exact(self, exponent: u32) -> Option<I256> {
        let division = divide_by_pow10(&self.limbs, exponent);
        (!division.sticky && division.top_remainder == 0)
            .then(|| I256::with_sign(self.negative, division.quotient))
    }

    /// `self / 10^exponent`, rounded half to even on the magnitude (so the
    /// rounding is symmetric in the sign — `rust_decimal`'s own rule).
    pub fn div_pow10_round_half_even(self, exponent: u32) -> I256 {
        if exponent == 0 {
            return self;
        }
        let division = divide_by_pow10(&self.limbs, exponent);
        // Half the divisor, in the units of the top remainder chunk.
        let half = 5 * 10u64.pow(division.top_digits - 1);
        let round_up = match division.top_remainder.cmp(&half) {
            Ordering::Greater => true,
            Ordering::Less => false,
            Ordering::Equal => division.sticky || division.quotient[0] & 1 == 1,
        };
        let mut quotient = division.quotient;
        if round_up {
            // Cannot carry out of the top limb: the quotient is at most
            // (2^256 − 1) / 10, so adding one stays far below 2^256.
            increment(&mut quotient);
        }
        I256::with_sign(self.negative, quotient)
    }

    /// The value as an `i128` when its magnitude is at most `max_magnitude`.
    pub fn to_i128_within(self, max_magnitude: u128) -> Option<i128> {
        if self.limbs[2] != 0 || self.limbs[3] != 0 {
            return None;
        }
        let magnitude = u128::from(self.limbs[0]) | (u128::from(self.limbs[1]) << 64);
        if magnitude > max_magnitude || magnitude > i128::MAX as u128 {
            return None;
        }
        let value = magnitude as i128;
        Some(if self.negative { -value } else { value })
    }

    /// A value from a sign and a magnitude, keeping zero non-negative.
    fn with_sign(negative: bool, limbs: [u64; 4]) -> I256 {
        I256 {
            negative: negative && limbs != [0; 4],
            limbs,
        }
    }
}

impl PartialOrd for I256 {
    fn partial_cmp(&self, other: &I256) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for I256 {
    fn cmp(&self, other: &I256) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => compare_magnitudes(&self.limbs, &other.limbs),
            (true, true) => compare_magnitudes(&other.limbs, &self.limbs),
        }
    }
}

fn compare_magnitudes(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

fn add_magnitudes(a: &[u64; 4], b: &[u64; 4]) -> Option<[u64; 4]> {
    let mut out = [0u64; 4];
    let mut carry = false;
    for index in 0..4 {
        let (sum, first) = a[index].overflowing_add(b[index]);
        let (sum, second) = sum.overflowing_add(u64::from(carry));
        out[index] = sum;
        carry = first || second;
    }
    (!carry).then_some(out)
}

/// `a − b` for `a ≥ b` (magnitudes).
fn subtract_magnitudes(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for index in 0..4 {
        let (difference, first) = a[index].overflowing_sub(b[index]);
        let (difference, second) = difference.overflowing_sub(u64::from(borrow));
        out[index] = difference;
        borrow = first || second;
    }
    out
}

fn multiply_small(limbs: &[u64; 4], factor: u64) -> Option<[u64; 4]> {
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    for index in 0..4 {
        let product = u128::from(limbs[index]) * u128::from(factor) + carry;
        out[index] = product as u64;
        carry = product >> 64;
    }
    (carry == 0).then_some(out)
}

fn increment(limbs: &mut [u64; 4]) {
    for limb in limbs.iter_mut() {
        let (next, carry) = limb.overflowing_add(1);
        *limb = next;
        if !carry {
            return;
        }
    }
}

/// `(⌊limbs / divisor⌋, limbs mod divisor)` for a non-zero `divisor`.
fn divide_small(limbs: &[u64; 4], divisor: u64) -> ([u64; 4], u64) {
    let mut quotient = [0u64; 4];
    let mut remainder: u128 = 0;
    for index in (0..4).rev() {
        let current = (remainder << 64) | u128::from(limbs[index]);
        quotient[index] = (current / u128::from(divisor)) as u64;
        remainder = current % u128::from(divisor);
    }
    (quotient, remainder as u64)
}

/// A magnitude divided by `10^exponent`, with what rounding needs to know.
struct PowerOfTenDivision {
    quotient: [u64; 4],
    /// The most significant chunk of the remainder: the remainder of the last
    /// (highest) division step, which divided by `10^top_digits`.
    top_remainder: u64,
    top_digits: u32,
    /// Whether any lower chunk of the remainder was non-zero.
    sticky: bool,
}

/// Divide by `10^exponent` in steps of at most `10^19`, lowest digits first,
/// so the last step's remainder is the remainder's leading digits and every
/// earlier one only matters as "non-zero" (the sticky bit).
fn divide_by_pow10(limbs: &[u64; 4], mut exponent: u32) -> PowerOfTenDivision {
    let mut quotient = *limbs;
    let mut sticky = false;
    let mut top_remainder = 0;
    let mut top_digits = 0;
    while exponent > 0 {
        let step = exponent.min(19);
        let divisor = if step == 19 {
            TEN_POW_19
        } else {
            10u64.pow(step)
        };
        let (next, remainder) = divide_small(&quotient, divisor);
        sticky |= top_remainder != 0;
        top_remainder = remainder;
        top_digits = step;
        quotient = next;
        exponent -= step;
    }
    PowerOfTenDivision {
        quotient,
        top_remainder,
        top_digits,
        sticky,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(text: &str) -> I256 {
        // Test helper: a decimal literal of any length, built with the
        // operations under test only where they are not what is being tested.
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text),
        };
        let mut value = I256::ZERO;
        for digit in digits.bytes() {
            value = value
                .checked_mul_pow10(1)
                .and_then(|shifted| shifted.checked_add(I256::from_i128(i128::from(digit - b'0'))))
                .expect("literal fits");
        }
        if negative {
            value.negated()
        } else {
            value
        }
    }

    const MAX_256: &str =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";

    #[test]
    fn edge_values_and_sign() {
        let max = big(MAX_256);
        assert_eq!(max.limbs, [u64::MAX; 4]);
        assert!(max.checked_add(I256::from_i128(1)).is_none());
        assert!(max.negated().checked_add(I256::from_i128(-1)).is_none());
        assert_eq!(
            max.checked_add(max.negated()),
            Some(I256::ZERO),
            "x + (−x) is a non-negative zero"
        );
        assert!(!I256::ZERO.negated().is_negative());
        assert_eq!(I256::ZERO.negated(), I256::ZERO);
        assert!(max.checked_mul_pow10(1).is_none());
        assert_eq!(I256::ZERO.checked_mul_pow10(76), Some(I256::ZERO));
        assert_eq!(big("1").checked_mul_pow10(78), None, "10^78 > 2^256");
        assert_eq!(big("2").checked_mul_pow10(77), None, "2 × 10^77 > 2^256");
        assert_eq!(
            big("1").checked_mul_pow10(77),
            Some(big(&format!("1{}", "0".repeat(77))))
        );
        for value in [i128::MIN + 1, -1, 0, 1, i128::MAX] {
            assert_eq!(
                I256::from_i128(value).to_i128_within(u128::MAX),
                Some(value)
            );
        }
        assert_eq!(I256::from_i128(i128::MIN).to_i128_within(u128::MAX), None);
        let mantissa_max = (1u128 << 96) - 1;
        let at_max = I256::from_i128(mantissa_max as i128);
        assert_eq!(
            at_max.to_i128_within(mantissa_max),
            Some(mantissa_max as i128)
        );
        assert_eq!(
            at_max.negated().to_i128_within(mantissa_max),
            Some(-(mantissa_max as i128))
        );
        assert_eq!(
            at_max
                .checked_add(I256::from_i128(1))
                .unwrap()
                .to_i128_within(mantissa_max),
            None
        );
        assert!(big("-5") < big("3") && big("-5") < big("-3") && big("7") > big("3"));
        // Mixed-sign addition in both magnitude orders.
        assert_eq!(big("5").checked_add(big("-8")), Some(big("-3")));
        assert_eq!(big("-5").checked_add(big("8")), Some(big("3")));
        // A carry across every limb and a borrow back across it.
        let limb_edge = big("18446744073709551615"); // 2^64 − 1
        let carried = limb_edge.checked_add(big("1")).unwrap();
        assert_eq!(carried.limbs, [0, 1, 0, 0]);
        assert_eq!(carried.checked_add(big("-1")), Some(limb_edge));
    }

    #[test]
    fn division_by_powers_of_ten() {
        let digits = "12345678901234567890123456789012345678901234567891";
        let value = big(&format!("{digits}0000000000"));
        assert_eq!(value.div_pow10_exact(10), Some(big(digits)));
        assert_eq!(value.div_pow10_exact(11), None);
        assert_eq!(
            value.negated().div_pow10_exact(10),
            Some(big(digits).negated())
        );
        let exact = big(&format!("-7{}", "0".repeat(40)));
        assert_eq!(exact.div_pow10_exact(40), Some(big("-7")));
        assert_eq!(exact.div_pow10_exact(41), None);
        assert_eq!(big("42").div_pow10_exact(0), Some(big("42")));
    }

    #[test]
    fn rounding_is_half_to_even_with_ties_both_ways_and_sticky_digits() {
        let cases = [
            // (value, digits dropped, expected)
            ("25", 1, "2"),   // tie → even (down)
            ("35", 1, "4"),   // tie → even (up)
            ("-25", 1, "-2"), // symmetric in the sign
            ("-35", 1, "-4"),
            ("251", 2, "3"), // below the tie → down (2.51 → 3)
            ("249", 2, "2"),
            ("250", 2, "2"), // 2.50 exact tie → even
            ("350", 2, "4"),
            ("26", 1, "3"),
            ("24", 1, "2"),
            ("4", 1, "0"),
            ("5", 1, "0"), // 0.5 → 0 (even)
            ("15", 1, "2"),
            ("-5", 1, "0"), // rounds to zero, never "-0"
            ("9", 1, "1"),
        ];
        for (value, dropped, expected) in cases {
            let rounded = big(value).div_pow10_round_half_even(dropped);
            assert_eq!(rounded, big(expected), "{value} / 10^{dropped}");
            assert!(!(rounded.is_zero() && rounded.is_negative()));
        }
        // A tie in the TOP chunk decided by a non-zero digit 19+ places below
        // it (the sticky bit across a 10^19 step).
        let tie = format!("2{}", "5".to_owned() + &"0".repeat(27));
        assert_eq!(big(&tie).div_pow10_round_half_even(28), big("2"));
        let above = format!("2{}", "5".to_owned() + &"0".repeat(26) + "1");
        assert_eq!(big(&above).div_pow10_round_half_even(28), big("3"));
        let odd_tie = format!("3{}", "5".to_owned() + &"0".repeat(27));
        assert_eq!(big(&odd_tie).div_pow10_round_half_even(28), big("4"));
        // Exactly 19 and 38 digits (whole steps) and 57 (three steps).
        for dropped in [19u32, 38, 57] {
            let half = format!("1{}", "5".to_owned() + &"0".repeat(dropped as usize - 1));
            assert_eq!(big(&half).div_pow10_round_half_even(dropped), big("2"));
            let below = format!("1{}", "4".to_owned() + &"9".repeat(dropped as usize - 1));
            assert_eq!(big(&below).div_pow10_round_half_even(dropped), big("1"));
        }
        // The largest magnitude still rounds without overflow.
        let max = big(MAX_256);
        assert_eq!(
            max.div_pow10_round_half_even(1),
            big("11579208923731619542357098500868790785326998466564056403945758400791312963994")
        );
        assert_eq!(big("7").div_pow10_round_half_even(0), big("7"));
    }
}
