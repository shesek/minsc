use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, Utc};

use bitcoin::relative::LockTime;

use crate::error::{ParseError, RuntimeError};
use crate::parser::ast::DurationUnit;

// Based on https://github.com/bitcoinjs/bip68, thanks bitcoinjs-lib folks!

const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;

const LOCKTIME_THRESHOLD: u32 = 500000000; // Tue Nov  5 00:53:20 1985 UTC

const BLOCKS_MAX: u32 = SEQUENCE_LOCKTIME_MASK; // 65535
const SECONDS_MAX: u32 = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY; // 33553920

// The default block interval. Can be overridden in Minsc by setting the `BLOCK_INTERVAL` variable
pub const BLOCK_INTERVAL: usize = 600;

pub fn relative_height_to_seq(num_blocks: u32) -> Result<u32, RuntimeError> {
    ensure!(
        num_blocks > 0 && num_blocks <= BLOCKS_MAX,
        RuntimeError::InvalidDurationBlocksOutOfRange
    );
    Ok(num_blocks)
}

pub fn relative_time_to_seq(
    parts: &[(f64, DurationUnit)],
    heightwise: bool,
    block_interval: u32,
) -> Result<u32, RuntimeError> {
    let seconds = parts
        .iter()
        .map(|(n, u)| match u {
            DurationUnit::Years => n * 31536000.0,
            DurationUnit::Months => n * 2629800.0, // 30.4375 days, divisible by 10 minutes
            DurationUnit::Weeks => n * 604800.0,
            DurationUnit::Days => n * 86400.0,
            DurationUnit::Hours => n * 3600.0,
            DurationUnit::Minutes => n * 60.0,
            DurationUnit::Seconds => *n,
        })
        .sum::<f64>();

    if heightwise {
        let block_interval = block_interval as f64;
        ensure!(
            seconds % block_interval == 0.0,
            RuntimeError::InvalidDurationHeightwise
        );
        relative_height_to_seq((seconds / block_interval) as u32)
    } else {
        ensure!(
            seconds > 0.0 && seconds <= SECONDS_MAX as f64,
            RuntimeError::InvalidDurationTimeOutOfRange
        );
        Ok(LockTime::from_seconds_ceil(seconds as u32)?.to_consensus_u32())
    }
}

pub fn parse_datetime(s: &str) -> Result<DateTime<Utc>, ParseError> {
    // Date always suffixed with T, hours optionally suffixed with Z
    let s = s.trim_end_matches('Z');
    let dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S").or_else(|_| {
        NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M").or_else(|_| -> Result<_, ParseError> {
            Ok(NaiveDate::parse_from_str(s, "%Y-%m-%dT")?
                .and_hms_opt(0, 0, 0)
                .unwrap())
        })
    })?;
    let dt = dt.and_utc();
    let ts = dt.timestamp();
    ensure!(
        ts >= LOCKTIME_THRESHOLD as i64 && ts <= u32::MAX as i64,
        ParseError::InvalidDateTimeOutOfRange // TODO add date string to error
    );
    Ok(dt)
}

pub fn fmt_timestamp(ts: u32) -> impl std::fmt::Display {
    lazy_static! {
        static ref MIN_TIME: NaiveTime = NaiveTime::from_hms_opt(0, 0, 0).unwrap();
    }

    let ts = DateTime::from_timestamp(ts as i64, 0).expect("u32 within range");
    if ts.time() == *MIN_TIME {
        ts.format("%Y-%m-%dT")
    } else {
        ts.format("%Y-%m-%dT%H:%M:%S")
    }
}
