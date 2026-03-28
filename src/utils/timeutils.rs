
pub fn unix_to_iso(ts: u64) -> String {
    let time_secs = ts % 86400;
    let mut days = ts / 86400;
    let h = time_secs / 3600;
    let m = (time_secs % 3600) / 60;
    let s = time_secs % 60;

    let mut year = 1970u32;
    loop {
        let diy = days_in_year(year);
        if days < diy {
            break;
        }
        days -= diy;
        year += 1;
    }

    let mdays = month_days(year);
    let mut month = 1u32;
    for &md in &mdays {
        if days < md {
            break;
        }
        days -= md;
        month += 1;
    }

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, days + 1, h, m, s)
}

fn days_in_year(y: u32) -> u64 {
    if is_leap(y) { 366 } else { 365 }
}

fn is_leap(y: u32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn month_days(year: u32) -> [u64; 12] {
    [31, if is_leap(year) { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
}
