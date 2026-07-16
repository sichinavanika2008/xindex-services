use crate::NativeRouterError;

pub(crate) fn parse_positive_u128(
    value: &str,
    field: &'static str,
) -> Result<u128, NativeRouterError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "not a canonical positive integer".to_string(),
        });
    }
    let parsed = value
        .parse::<u128>()
        .map_err(|_| NativeRouterError::InvalidField {
            field,
            reason: "outside uint128 or not decimal".to_string(),
        })?;
    if parsed == 0 {
        return Err(NativeRouterError::InvalidField {
            field,
            reason: "must be non-zero".to_string(),
        });
    }
    Ok(parsed)
}

fn scale_factor(delta: u8) -> Result<u128, NativeRouterError> {
    10u128
        .checked_pow(u32::from(delta))
        .ok_or(NativeRouterError::Policy("decimal scale overflows uint128"))
}

pub(crate) fn scale_exact(
    amount: u128,
    from_decimals: u8,
    to_decimals: u8,
) -> Result<u128, NativeRouterError> {
    if from_decimals > 18 || to_decimals > 18 {
        return Err(NativeRouterError::Policy("asset decimals exceed 18"));
    }
    match from_decimals.cmp(&to_decimals) {
        std::cmp::Ordering::Equal => Ok(amount),
        std::cmp::Ordering::Less => amount
            .checked_mul(scale_factor(to_decimals - from_decimals)?)
            .ok_or(NativeRouterError::Policy("scaled amount overflows uint128")),
        std::cmp::Ordering::Greater => {
            let divisor = scale_factor(from_decimals - to_decimals)?;
            if !amount.is_multiple_of(divisor) {
                return Err(NativeRouterError::Policy(
                    "amount loses precision at provider scale",
                ));
            }
            Ok(amount / divisor)
        }
    }
}

pub(crate) fn scale_floor(
    amount: u128,
    from_decimals: u8,
    to_decimals: u8,
) -> Result<u128, NativeRouterError> {
    if from_decimals <= to_decimals {
        return scale_exact(amount, from_decimals, to_decimals);
    }
    Ok(amount / scale_factor(from_decimals - to_decimals)?)
}

pub(crate) fn scale_ceil(
    amount: u128,
    from_decimals: u8,
    to_decimals: u8,
) -> Result<u128, NativeRouterError> {
    if amount == 0 {
        return Ok(0);
    }
    if from_decimals <= to_decimals {
        return scale_exact(amount, from_decimals, to_decimals);
    }
    let divisor = scale_factor(from_decimals - to_decimals)?;
    Ok(amount.saturating_sub(1) / divisor + 1)
}

pub(crate) fn ceil_bps(numerator: u128, denominator: u128) -> Result<u16, NativeRouterError> {
    if denominator == 0 || numerator > denominator {
        return Err(NativeRouterError::Policy("invalid basis-point ratio"));
    }
    let scaled = numerator
        .checked_mul(10_000)
        .ok_or(NativeRouterError::Policy(
            "basis-point calculation overflow",
        ))?;
    let value = scaled.saturating_add(denominator - 1) / denominator;
    u16::try_from(value).map_err(|_| NativeRouterError::Policy("basis-point value exceeds uint16"))
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test fixtures must fail loudly")]

    use super::*;

    #[test]
    fn scaling_is_explicit_about_rounding() {
        assert_eq!(scale_exact(1_000_000, 6, 8).expect("scale"), 100_000_000);
        assert!(scale_exact(100_000_001, 8, 6).is_err());
        assert_eq!(scale_floor(100_000_099, 8, 6).expect("floor"), 1_000_000);
        assert_eq!(scale_ceil(100_000_001, 8, 6).expect("ceil"), 1_000_001);
        assert_eq!(scale_ceil(0, 8, 6).expect("zero"), 0);
    }
}
