use std::time::Duration;

pub(super) fn parse_lifetime(value: &str) -> Result<String, &'static str> {
    duration(value)
        .filter(|duration| duration.as_secs() >= 1)
        .ok_or("Use an ISO 8601 duration of at least one second, e.g. PT15M or P1D")
        .map(|_| value.to_ascii_uppercase())
}

/// Parses the nonnegative day/time form accepted by the server's java.time.Duration.
pub(super) fn duration(value: &str) -> Option<Duration> {
    let value = value.to_ascii_uppercase();
    let value = value.strip_prefix('P')?;
    let (days, time) = value
        .split_once('T')
        .map_or((value, None), |(days, time)| (days, Some(time)));
    let mut seconds = if days.is_empty() {
        0
    } else {
        integer(days.strip_suffix('D')?)?.checked_mul(86_400)?
    };
    let mut nanos = 0;
    if let Some(time) = time {
        if time.is_empty() {
            return None;
        }
        let mut previous_unit = 3;
        for component in time.split_inclusive(['H', 'M', 'S']) {
            let unit = component.chars().next_back()?;
            let (rank, multiplier) = match unit {
                'H' => (2, 3_600),
                'M' => (1, 60),
                'S' => (0, 1),
                _ => return None,
            };
            if rank >= previous_unit {
                return None;
            }
            previous_unit = rank;
            let mut number = component.strip_suffix(unit)?;
            if unit == 'S'
                && let Some((whole, fraction)) = number.split_once(['.', ','])
            {
                if fraction.len() > 9 {
                    return None;
                }
                nanos =
                    u32::try_from(integer(fraction)?).ok()? * 10_u32.pow(9 - fraction.len() as u32);
                number = whole;
            }
            seconds = seconds.checked_add(integer(number)?.checked_mul(multiplier)?)?;
        }
    } else if days.is_empty() {
        return None;
    }
    (seconds <= i64::MAX as u64).then(|| Duration::new(seconds, nanos))
}

fn integer(value: &str) -> Option<u64> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_and_compares_iso_lifetimes() {
        assert_eq!(parse_lifetime("p1dt1h").unwrap(), "P1DT1H");
        assert_eq!(duration("PT1H"), duration("PT60M"));
        assert_eq!(duration("PT1.5S"), Some(Duration::new(1, 500_000_000)));
        for invalid in [
            "",
            "5m",
            "P",
            "PT",
            "P1DT",
            "PT0.9S",
            "PT0S",
            "-PT5M",
            "PT1M1H",
            "PT1S1S",
            "PT1.1M",
            "PT1.1234567890S",
            "P1M",
            "PT9223372036854775808S",
        ] {
            assert!(parse_lifetime(invalid).is_err(), "{invalid}");
        }
    }
}
