use chrono::{NaiveDate, NaiveDateTime};

use crate::ast::{Duration, DurationPart};
use crate::error::{Error, Result};

// Based on https://github.com/bitcoinjs/bip68, thanks bitcoinjs-lib folks!

const SEQUENCE_LOCKTIME_MASK: usize = 0x0000ffff;
const SEQUENCE_LOCKTIME_GRANULARITY: usize = 9;
const SEQUENCE_LOCKTIME_TYPE_FLAG: usize = 1 << 22;

const LOCKTIME_THRESHOLD: usize = 500000000; // Tue Nov  5 00:53:20 1985 UTC

const BLOCKS_MAX: usize = SEQUENCE_LOCKTIME_MASK; // 65535
const SECONDS_MAX: usize = SEQUENCE_LOCKTIME_MASK << SEQUENCE_LOCKTIME_GRANULARITY; // 33553920
const SECONDS_MOD: usize = 1 << SEQUENCE_LOCKTIME_GRANULARITY; // 512

pub fn duration_to_seq(duration: &Duration) -> Result<usize> {
    match duration {
        Duration::BlockHeight(num_blocks) => rel_height_to_seq(*num_blocks),
        Duration::BlockTime { parts, blockwise } => rel_time_to_seq(parts, *blockwise),
    }
}

fn rel_height_to_seq(num_blocks: usize) -> Result<usize> {
    ensure!(
        num_blocks > 0 && num_blocks <= BLOCKS_MAX,
        Error::InvalidDurationBlocksOutOfRange
    );
    Ok(num_blocks)
}

fn rel_time_to_seq(parts: &[DurationPart], blockwise: bool) -> Result<usize> {
    let seconds = parts
        .iter()
        .map(|p| match p {
            DurationPart::Years(n) => n * 31536000.0,
            DurationPart::Months(n) => n * 2629800.0, // 30.4375 days, divisible by 10 minutes
            DurationPart::Weeks(n) => n * 604800.0,
            DurationPart::Days(n) => n * 86400.0,
            DurationPart::Hours(n) => n * 3600.0,
            DurationPart::Minutes(n) => n * 60.0,
            DurationPart::Seconds(n) => *n,
        })
        .sum::<f64>();

    if blockwise {
        ensure!(seconds % 600.0 == 0.0, Error::InvalidDurationBlockwise);
        return rel_height_to_seq((seconds / 600.0) as usize);
    }

    ensure!(
        seconds > 0.0 && seconds <= SECONDS_MAX as f64,
        Error::InvalidDurationTimeOutOfRange
    );

    let units = (seconds / SECONDS_MOD as f64).ceil() as usize;
    Ok(SEQUENCE_LOCKTIME_TYPE_FLAG | units)
}

pub fn parse_datetime(s: &str) -> Result<usize> {
    let ts = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M")
        .or_else(|_| Ok::<_, Error>(NaiveDate::parse_from_str(s, "%Y-%m-%d")?.and_hms(0, 0, 0)))?
        .timestamp();
    ensure!(
        ts >= LOCKTIME_THRESHOLD as i64,
        Error::InvalidDateTimeOutOfRange
    );
    Ok(ts as usize)
}
