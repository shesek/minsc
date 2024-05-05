use chrono::{NaiveDate, NaiveDateTime};

use crate::error::{ParseError, RuntimeError};
use crate::parser::ast::DurationUnit;

// Based on https://github.com/bitcoinjs/bip68, thanks bitcoinjs-lib folks!

const SEQUENCE_LOCKTIME_MASK: u32 = 0x0000ffff;
const SEQUENCE_LOCKTIME_GRANULARITY: u32 = 9;
const SEQUENCE_LOCKTIME_TYPE_FLAG: u32 = 1 << 22;

const LOCKTIME_THRESHOLD: u32 = 500000000; // Tue Nov  5 00:53:20 1985 UTC

const BLOCKS_MAX: u32 = SEQUENCE_LOCKTIME_MASK; // 65535
const SECONDS_MAX: u32 = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY; // 33553920
const SECONDS_MOD: u32 = 1 << SEQUENCE_LOCKTIME_GRANULARITY; // 512

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

        let units = (seconds / SECONDS_MOD as f64).ceil() as u32;
        Ok(SEQUENCE_LOCKTIME_TYPE_FLAG | units)
    }
}

// XXX add date string to error
pub fn parse_datetime(s: &str) -> Result<NaiveDateTime, ParseError> {
    let dt = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M").or_else(|_| {
        Ok::<_, ParseError>(NaiveDate::parse_from_str(s, "%Y-%m-%d")?.and_hms(0, 0, 0))
    })?;
    let ts = dt.timestamp();
    ensure!(
        ts >= LOCKTIME_THRESHOLD as i64 && ts <= u32::max_value() as i64,
        ParseError::InvalidDateTimeOutOfRange
    );
    Ok(dt)
}
