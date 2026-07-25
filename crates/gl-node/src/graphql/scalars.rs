use async_graphql::{InputValueError, InputValueResult, Scalar, ScalarType, Value};
use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::str::FromStr;

/// ISO-8601 calendar date scalar (`YYYY-MM-DD`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DateScalar(pub NaiveDate);

#[Scalar(name = "Date")]
impl ScalarType for DateScalar {
    fn parse(value: Value) -> InputValueResult<Self> {
        match &value {
            Value::String(date_string) => {
                let date = NaiveDate::parse_from_str(date_string, "%Y-%m-%d")
                    .map_err(|_| InputValueError::custom("Invalid date, expected YYYY-MM-DD"))?;
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
    fn parse(value: Value) -> InputValueResult<Self> {
        match &value {
            Value::String(decimal_string) => {
                let decimal = Decimal::from_str(decimal_string)
                    .map_err(|_| InputValueError::custom("Invalid decimal string"))?;
                Ok(DecimalScalar(decimal))
            }
            // Also accept JSON numbers for convenience.
            Value::Number(number) => {
                let decimal = Decimal::from_str(&number.to_string()).map_err(|_| {
                    InputValueError::custom("Number cannot be represented as decimal")
                })?;
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
    fn test_decimal_scalar_round_trip() {
        let decimal = DecimalScalar(Decimal::from_str("1000.00").unwrap());
        let value = decimal.to_value();
        assert_eq!(value, Value::String("1000.00".to_owned()));
        let parsed = DecimalScalar::parse(value).unwrap();
        assert_eq!(parsed, decimal);
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
