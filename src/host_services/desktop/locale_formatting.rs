use std::sync::OnceLock;

use bytesize::ByteSize;
use fixed_decimal::Decimal;
use icu::{
    datetime::{
        DateTimeFormatter,
        fieldsets::{YMD, YMDT},
    },
    locale::{Locale, locale},
};
use icu_experimental::relativetime::{
    RelativeTimeFormatter, RelativeTimeFormatterOptions, options::Numeric,
};
use jiff::{SignedDuration, Timestamp, civil, tz::TimeZone};
use relm4::gtk::glib;
use writeable::Writeable;

const HOURS_PER_DAY: i64 = 24;
const LOCALE_INDEPENDENT_NAMES: [&str; 2] = ["C", "POSIX"];

#[derive(Debug, thiserror::Error)]
pub enum LocaleDataMissing {
    #[error("no date formatting data: {0}")]
    DateFormatting(#[from] icu::datetime::DateTimeFormatterLoadError),
    #[error("no relative time data: {0}")]
    RelativeTime(#[from] icu_provider::DataError),
}

pub struct MomentFormatters {
    date_time_formatter: DateTimeFormatter<YMDT>,
    date_formatter: DateTimeFormatter<YMD>,
    seconds_formatter: RelativeTimeFormatter,
    minutes_formatter: RelativeTimeFormatter,
    hours_formatter: RelativeTimeFormatter,
    days_formatter: RelativeTimeFormatter,
}

fn locale_from_glib_name(glib_locale_name: &str) -> Option<Locale> {
    let language_tag = glib_locale_name
        .split(['.', '@'])
        .next()
        .unwrap_or_default()
        .replace('_', "-");
    if language_tag.is_empty() || LOCALE_INDEPENDENT_NAMES.contains(&language_tag.as_str()) {
        return None;
    }
    Locale::try_from_str(&language_tag).ok()
}

fn host_locale_for(locale_category: &str) -> Locale {
    glib::language_names_with_category(locale_category)
        .iter()
        .find_map(|glib_locale_name| locale_from_glib_name(glib_locale_name))
        .unwrap_or(locale!("en"))
}

fn named_relative_options() -> RelativeTimeFormatterOptions {
    RelativeTimeFormatterOptions::default().with_numeric(Numeric::Auto)
}

fn written_text(formatted_value: &impl Writeable) -> String {
    formatted_value.write_to_string().into_owned()
}

impl MomentFormatters {
    pub fn try_for_locales(
        time_locale: &Locale,
        messages_locale: &Locale,
    ) -> Result<Self, LocaleDataMissing> {
        let relative_preferences = messages_locale.clone().into();
        Ok(Self {
            date_time_formatter: DateTimeFormatter::try_new(
                time_locale.clone().into(),
                YMD::medium().with_time_hm(),
            )?,
            date_formatter: DateTimeFormatter::try_new(time_locale.clone().into(), YMD::medium())?,
            seconds_formatter: RelativeTimeFormatter::try_new_long_second(
                relative_preferences,
                named_relative_options(),
            )?,
            minutes_formatter: RelativeTimeFormatter::try_new_long_minute(
                relative_preferences,
                named_relative_options(),
            )?,
            hours_formatter: RelativeTimeFormatter::try_new_long_hour(
                relative_preferences,
                named_relative_options(),
            )?,
            days_formatter: RelativeTimeFormatter::try_new_long_day(
                relative_preferences,
                named_relative_options(),
            )?,
        })
    }

    pub fn format_wall_clock(&self, wall_clock: &civil::DateTime) -> String {
        written_text(&self.date_time_formatter.format(wall_clock))
    }

    pub fn format_calendar_date(&self, calendar_date: &civil::Date) -> String {
        written_text(&self.date_formatter.format(calendar_date))
    }

    pub fn exact_moment_text(&self, moment: Timestamp) -> String {
        self.format_wall_clock(&moment.to_zoned(TimeZone::system()).datetime())
    }

    pub fn calendar_date_text(&self, moment: Timestamp) -> String {
        self.format_calendar_date(&moment.to_zoned(TimeZone::system()).date())
    }

    pub fn relative_moment_text(&self, moment: Timestamp, reference_moment: Timestamp) -> String {
        let distance = moment.duration_since(reference_moment);
        let elapsed = distance.abs();
        let unit_count = if elapsed < SignedDuration::from_mins(1) {
            return written_text(&self.seconds_formatter.format(Decimal::from(0)));
        } else if elapsed < SignedDuration::from_hours(1) {
            return written_text(
                &self
                    .minutes_formatter
                    .format(Decimal::from(distance.as_mins())),
            );
        } else if elapsed < SignedDuration::from_hours(HOURS_PER_DAY) {
            return written_text(
                &self
                    .hours_formatter
                    .format(Decimal::from(distance.as_hours())),
            );
        } else {
            distance.as_hours() / HOURS_PER_DAY
        };
        written_text(&self.days_formatter.format(Decimal::from(unit_count)))
    }
}

pub fn host_moment_formatters() -> &'static MomentFormatters {
    static HOST_MOMENT_FORMATTERS: OnceLock<MomentFormatters> = OnceLock::new();
    HOST_MOMENT_FORMATTERS.get_or_init(|| {
        MomentFormatters::try_for_locales(
            &host_locale_for("LC_TIME"),
            &host_locale_for("LC_MESSAGES"),
        )
        .or_else(|_missing_locale_data| {
            MomentFormatters::try_for_locales(&locale!("en"), &locale!("en"))
        })
        .expect("compiled ICU data always contains English")
    })
}

pub fn exact_local_time_text(moment: Timestamp) -> String {
    host_moment_formatters().exact_moment_text(moment)
}

pub fn byte_size_text(byte_size: ByteSize) -> String {
    glib::format_size_full(byte_size.as_u64(), glib::FormatSizeFlags::IEC_UNITS).into()
}

pub fn exact_byte_size_text(byte_size: ByteSize) -> String {
    glib::format_size_full(
        byte_size.as_u64(),
        glib::FormatSizeFlags::IEC_UNITS | glib::FormatSizeFlags::LONG_FORMAT,
    )
    .into()
}

#[cfg(test)]
mod locale_formatting_tests {
    use super::*;

    const REFERENCE_MOMENT: Timestamp = Timestamp::constant(1_794_200_000, 0);

    fn formatters_for(locale_name: Locale) -> MomentFormatters {
        MomentFormatters::try_for_locales(&locale_name, &locale_name).unwrap()
    }

    fn sample_wall_clock() -> civil::DateTime {
        civil::date(2026, 11, 6).at(17, 45, 20, 0)
    }

    #[test]
    fn english_relative_moments_read_naturally() {
        let english_formatters = formatters_for(locale!("en"));
        assert_eq!(
            english_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_mins(12),
                REFERENCE_MOMENT
            ),
            "12 minutes ago"
        );
        assert_eq!(
            english_formatters.relative_moment_text(
                REFERENCE_MOMENT + SignedDuration::from_hours(72) + SignedDuration::from_secs(5),
                REFERENCE_MOMENT
            ),
            "in 3 days"
        );
        assert_eq!(
            english_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_secs(20),
                REFERENCE_MOMENT
            ),
            "now"
        );
        assert_eq!(
            english_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_hours(30),
                REFERENCE_MOMENT
            ),
            "yesterday"
        );
        assert_eq!(
            english_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_hours(4 * 24),
                REFERENCE_MOMENT
            ),
            "4 days ago"
        );
    }

    #[test]
    fn dutch_relative_moments_use_dutch_words() {
        let dutch_formatters = formatters_for(locale!("nl"));
        assert_eq!(
            dutch_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_hours(24),
                REFERENCE_MOMENT
            ),
            "gisteren"
        );
        assert_eq!(
            dutch_formatters.relative_moment_text(
                REFERENCE_MOMENT - SignedDuration::from_hours(3 * 24),
                REFERENCE_MOMENT
            ),
            "3 dagen geleden"
        );
    }

    #[test]
    fn dates_follow_the_locale_order() {
        assert_eq!(
            formatters_for(locale!("en-US")).format_calendar_date(&sample_wall_clock().date()),
            "Nov 6, 2026"
        );
        assert_eq!(
            formatters_for(locale!("nl-BE")).format_calendar_date(&sample_wall_clock().date()),
            "6 nov 2026"
        );
        assert_eq!(
            formatters_for(locale!("de")).format_calendar_date(&sample_wall_clock().date()),
            "06.11.2026"
        );
    }

    #[test]
    fn times_of_day_follow_the_locale_clock() {
        assert!(
            formatters_for(locale!("nl-BE"))
                .format_wall_clock(&sample_wall_clock())
                .contains("17:45")
        );
        assert!(
            formatters_for(locale!("en-US"))
                .format_wall_clock(&sample_wall_clock())
                .contains("5:45")
        );
    }

    #[test]
    fn byte_sizes_use_binary_units_and_keep_the_exact_count_when_asked() {
        assert_eq!(byte_size_text(ByteSize::b(15)), "15 bytes");
        assert_eq!(byte_size_text(ByteSize::b(27_474_124)), "26.2\u{a0}MiB");
        assert_eq!(
            exact_byte_size_text(ByteSize::b(27_474_124)),
            "26.2\u{a0}MiB (27474124 bytes)"
        );
    }

    #[test]
    fn glib_locale_names_become_language_tags() {
        assert_eq!(
            locale_from_glib_name("nl_BE.UTF-8@euro"),
            Some(locale!("nl-BE"))
        );
        assert_eq!(locale_from_glib_name("C"), None);
        assert_eq!(locale_from_glib_name("POSIX"), None);
    }
}
