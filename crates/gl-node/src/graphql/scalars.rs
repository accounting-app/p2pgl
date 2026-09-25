use async_graphql::{InputValueError, InputValueResult, Scalar, ScalarType, Value};
use chrono::{Datelike, NaiveDate};
use rust_decimal::Decimal;

/// Smallest year the ledger's `.bean` file grammar can express (H-04).
const MIN_LEDGER_YEAR: i32 = 1;
/// Largest year the ledger's `.bean` file grammar can express (H-04).
const MAX_LEDGER_YEAR: i32 = 9999;

/// ISO-8601 calendar date scalar (`YYYY-MM-DD`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateScalar(pub NaiveDate);

#[Scalar(name = "Date")]
impl ScalarType for DateScalar {
    /// Parse a wire date, rejecting years the ledger file can never re-parse.
    ///
    /// (H-04) `chrono`'s `%Y` accepts an explicitly signed year of unlimited
    /// width — `"+10000-01-01"`, `"-0001-01-01"` — and its formatter emits that
    /// sign back for every year outside `0..=9999`. The ledger's own file
    /// grammar (`read_date` in `ledger::parse`) requires exactly four leading
    /// ASCII digits, so a signed year that reaches the serializer produces a
    /// `.bean` file no later `LedgerService::boot` can parse: one accepted
    /// mutation permanently bricks the node. Clamp at the API edge, before the
    /// date can ever be persisted.
    fn parse(value: Value) -> InputValueResult<Self> {
        match &value {
            Value::String(date_string) => {
                let date = NaiveDate::parse_from_str(date_string, "%Y-%m-%d")
                    .map_err(|_| InputValueError::custom("Invalid date, expected YYYY-MM-DD"))?;
                if !(MIN_LEDGER_YEAR..=MAX_LEDGER_YEAR).contains(&date.year()) {
                    return Err(InputValueError::custom(
                        "date year must be between 0001 and 9999",
                    ));
                }
                Ok(DateScalar(date))
            }
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.0.format("%Y-%m-%d").to_string())
    }
}

/// Arbitrary-precision decimal scalar, serialized as a string on the wire (§3.1 / I4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecimalScalar(pub Decimal);

#[Scalar(name = "Decimal")]
impl ScalarType for DecimalScalar {
    /// Parse a wire decimal, refusing one outside the ledger's amount cap.
    ///
    /// (H-17, T76) Every `Decimal` a client sends is an amount the ledger
    /// would store and sum — a posting's units, cost or price — so the cap
    /// (`|amount| ≤` [`ledger::limits::MAX_AMOUNT_MAGNITUDE`], `10^21`, at any
    /// precision) applies here, at the API edge, through the same
    /// `check_amount_cap` `validate_transaction` and the `.bean` parser use.
    /// `validate_transaction` still re-checks it: this is the early, typed
    /// refusal, not the only one. `from_str_exact` for the same reason the
    /// parser uses it: `from_str` silently rounds a fraction past 28 digits, so
    /// the value checked and stored would not be the value sent.
    ///
    /// Output values (balances, report totals) are sums and may legitimately
    /// exceed the cap; they only ever go through [`Self::to_value`].
    fn parse(value: Value) -> InputValueResult<Self> {
        match &value {
            Value::String(decimal_string) => {
                let decimal = Decimal::from_str_exact(decimal_string).map_err(|_| {
                    // T83 / L-92: say why when the spelling is too long.
                    InputValueError::custom(
                        ledger::validate::explain_unrepresentable_amount(decimal_string)
                            .unwrap_or_else(|| "Invalid decimal string".to_owned()),
                    )
                })?;
                ledger::validate::check_amount_cap("Decimal", decimal)
                    .map_err(|error| InputValueError::custom(error.to_string()))?;
                Ok(DecimalScalar(decimal))
            }
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.0.to_string())
    }
}

/// Content-hash transaction identifier (64-character lowercase hex SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(pub String);

#[Scalar(name = "TxId")]
impl ScalarType for TransactionId {
    fn parse(value: Value) -> InputValueResult<Self> {
        match &value {
            Value::String(hex_string) => {
                if hex_string.len() == 64
                    && hex_string
                        .chars()
                        .all(|character| character.is_ascii_hexdigit())
                {
                    Ok(TransactionId(hex_string.to_lowercase()))
                } else {
                    Err(InputValueError::custom(
                        "TxId must be a 64-character hex string (SHA-256)",
                    ))
                }
            }
            _ => Err(InputValueError::expected_type(value)),
        }
    }

    fn to_value(&self) -> Value {
        Value::String(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// L-92 (T83): the scalar says why an over-long amount spelling is
    /// refused, instead of "Invalid decimal string".
    #[test]
    fn l92_the_scalar_explains_an_over_long_amount() {
        let error = <DecimalScalar as ScalarType>::parse(Value::String(
            "1000000000000000000000.00000000".to_owned(),
        ))
        .expect_err("30 digits");
        let message = format!("{error:?}");
        assert!(
            message.contains("7 decimal places") && message.contains("L-92"),
            "{message}"
        );
        let error = <DecimalScalar as ScalarType>::parse(Value::String("12x".to_owned()))
            .expect_err("malformed");
        assert!(format!("{error:?}").contains("Invalid decimal string"));
    }

    #[test]
    fn test_date_scalar_round_trip() {
        let date = DateScalar(NaiveDate::from_ymd_opt(2024, 1, 15).unwrap());
        let value = date.to_value();
        assert_eq!(value, Value::String("2024-01-15".to_owned()));
        let parsed = DateScalar::parse(value).unwrap();
        assert_eq!(parsed, date);
    }

    #[test]
    fn test_date_scalar_rejects_invalid() {
        let result = DateScalar::parse(Value::String("2024-13-01".to_owned()));
        assert!(result.is_err());
    }

    #[test]
    fn test_date_scalar_rejects_out_of_range_years() {
        // H-04: chrono accepts a signed year of any width, and re-emits the
        // sign — the ledger's file grammar can never read one back, so a single
        // accepted value would brick the node at its next boot. `10000-01-01`
        // (5 digits, unsigned) is rejected by chrono itself; assert the scalar
        // refuses it either way so the guarantee does not rest on chrono.
        for date_string in ["+10000-01-01", "-0001-01-01", "0000-01-01", "10000-01-01"] {
            let result = DateScalar::parse(Value::String(date_string.to_owned()));
            assert!(
                result.is_err(),
                "expected {date_string} to be rejected as out of range"
            );
        }
    }

    #[test]
    fn test_date_scalar_accepts_range_boundaries() {
        // The first and last dates the `.bean` grammar can round-trip.
        for date_string in ["0001-01-01", "9999-12-31"] {
            let parsed = DateScalar::parse(Value::String(date_string.to_owned()))
                .unwrap_or_else(|_| panic!("expected {date_string} to be accepted"));
            assert_eq!(parsed.to_value(), Value::String(date_string.to_owned()));
        }
    }

    #[test]
    fn test_decimal_scalar_round_trip() {
        let decimal = DecimalScalar(Decimal::from_str("1000.00").unwrap());
        let value = decimal.to_value();
        assert_eq!(value, Value::String("1000.00".to_owned()));
        let parsed = DecimalScalar::parse(value).unwrap();
        assert_eq!(parsed, decimal);
    }

    #[test]
    fn test_decimal_scalar_rejects_json_number() {
        let result = DecimalScalar::parse(Value::Number(serde_json::Number::from(100)));
        assert!(result.is_err(), "Decimal must be a string on the wire (I4)");
    }

    /// H-17 / T76: an amount past the magnitude cap is refused at the API
    /// edge — including the `±Decimal::MAX` pair the B6 proof used — while
    /// `10^21` itself (inclusive) and any precision inside it parse: trailing
    /// zeros are precision, not magnitude (M-50).
    #[test]
    fn test_decimal_scalar_enforces_the_amount_cap() {
        for over_cap in [
            "79228162514264337593543950335",   // Decimal::MAX
            "-79228162514264337593543950335",  // Decimal::MIN
            "1000000000000000000001",          // 10^21 + 1
            "-1000000000000000000000.0000001", // one ulp past −10^21
        ] {
            let error = DecimalScalar::parse(Value::String(over_cap.to_owned()))
                .expect_err(&format!("{over_cap} must be refused"));
            assert!(
                format!("{error:?}").contains("H-17"),
                "{over_cap}: refusal must name the cap, got {error:?}"
            );
        }
        for in_cap in [
            "1000000000000000000000",
            "-1000000000000000000000",
            "1000000000000000000000.0000000",
            "10000000000000.00000000",
            "1.000000000000000000000",
            "9999999999999.99999999",
            "792281625142643.37593543950335",
            "0.0000000000000000000000000001",
        ] {
            let parsed = DecimalScalar::parse(Value::String(in_cap.to_owned()))
                .unwrap_or_else(|_| panic!("{in_cap} must be accepted"));
            assert_eq!(parsed.to_value(), Value::String(in_cap.to_owned()));
        }
        // No silent rounding: a 29th fractional digit is refused, not dropped.
        assert!(
            DecimalScalar::parse(Value::String("0.00000000000000000000000000001".to_owned()))
                .is_err()
        );
    }

    #[test]
    fn test_decimal_scalar_negative() {
        let decimal = DecimalScalar(Decimal::from_str("-500.25").unwrap());
        let value = decimal.to_value();
        assert_eq!(value, Value::String("-500.25".to_owned()));
    }

    #[test]
    fn test_transaction_id_valid() {
        let hex = "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f";
        let result = TransactionId::parse(Value::String(hex.to_owned()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, hex);
    }

    #[test]
    fn test_transaction_id_rejects_short() {
        let result = TransactionId::parse(Value::String("abcdef".to_owned()));
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_id_rejects_non_hex() {
        let non_hex = "zz4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f";
        let result = TransactionId::parse(Value::String(non_hex.to_owned()));
        assert!(result.is_err());
    }

    #[test]
    fn test_transaction_id_normalizes_to_lowercase() {
        let upper_hex = "DD4A9EC5EC298BE6EDAA02C4408C0B1CB1B25EB51426599B7EDA600CFC5FA88F";
        let result = TransactionId::parse(Value::String(upper_hex.to_owned()));
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, upper_hex.to_lowercase());
    }
}
