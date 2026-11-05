use std::f64::consts::{FRAC_PI_2, PI};

use gettextrs::ngettext;
use relm4::{gtk, gtk::prelude::*};

use crate::activity_history::{
    activity_entry_row::formatted_local_time, scan_activity_statistics::ScanActivityBucket,
};

const CHART_HEIGHT: i32 = 96;
const SECONDS_PER_DAY: i64 = 86_400;
const BAR_WIDTH: f64 = 10.0;
const BAR_GAP: f64 = 2.0;
const BAR_CORNER_RADIUS: f64 = 4.0;

#[derive(Clone, Copy)]
struct ChartColor {
    red: f64,
    green: f64,
    blue: f64,
}

const SCAN_BAR_COLOR: ChartColor = ChartColor {
    red: 0.208,
    green: 0.518,
    blue: 0.894,
};
const THREAT_BAR_COLOR: ChartColor = ChartColor {
    red: 0.902,
    green: 0.380,
    blue: 0.0,
};

fn trace_bar_path(
    drawing_context: &gtk::cairo::Context,
    bar_left: f64,
    bar_height: f64,
    baseline: f64,
) {
    let corner_radius = BAR_CORNER_RADIUS.min(bar_height).min(BAR_WIDTH / 2.0);
    let bar_top = baseline - bar_height;
    drawing_context.new_path();
    drawing_context.move_to(bar_left, baseline);
    drawing_context.line_to(bar_left, bar_top + corner_radius);
    drawing_context.arc(
        bar_left + corner_radius,
        bar_top + corner_radius,
        corner_radius,
        PI,
        PI + FRAC_PI_2,
    );
    drawing_context.arc(
        bar_left + BAR_WIDTH - corner_radius,
        bar_top + corner_radius,
        corner_radius,
        PI + FRAC_PI_2,
        2.0 * PI,
    );
    drawing_context.line_to(bar_left + BAR_WIDTH, baseline);
    drawing_context.close_path();
}

fn draw_bar(
    drawing_context: &gtk::cairo::Context,
    bar_left: f64,
    bar_value: u64,
    largest_value: u64,
    bar_color: ChartColor,
    baseline: f64,
) {
    if bar_value == 0 {
        return;
    }
    let bar_height = (bar_value as f64 / largest_value as f64 * baseline).max(2.0);
    trace_bar_path(drawing_context, bar_left, bar_height, baseline);
    drawing_context.set_source_rgb(bar_color.red, bar_color.green, bar_color.blue);
    let _surface_error_reported_by_gtk = drawing_context.fill();
}

fn bucket_tooltip(activity_bucket: &ScanActivityBucket) -> String {
    let scan_text = ngettext(
        "{count} scan",
        "{count} scans",
        u32::try_from(activity_bucket.scan_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &activity_bucket.scan_count.to_string());
    let threat_text = ngettext(
        "{count} threat",
        "{count} threats",
        u32::try_from(activity_bucket.threat_count).unwrap_or(u32::MAX),
    )
    .replace("{count}", &activity_bucket.threat_count.to_string());
    format!(
        "{} – {}\n{scan_text}, {threat_text}",
        formatted_local_time(activity_bucket.bucket_start_unix),
        formatted_local_time(activity_bucket.bucket_end_unix)
    )
}

fn bucket_date_label(activity_bucket: &ScanActivityBucket) -> String {
    let spans_under_a_day =
        activity_bucket.bucket_end_unix - activity_bucket.bucket_start_unix < SECONDS_PER_DAY;
    gtk::glib::DateTime::from_unix_local(activity_bucket.bucket_end_unix)
        .and_then(|local_time| local_time.format(if spans_under_a_day { "%H:%M" } else { "%d/%m" }))
        .map(String::from)
        .unwrap_or_default()
}

fn bucket_column(
    activity_bucket: ScanActivityBucket,
    largest_value: u64,
    shows_label: bool,
) -> gtk::Box {
    let bar_area = gtk::DrawingArea::builder()
        .content_height(CHART_HEIGHT)
        .hexpand(true)
        .tooltip_text(bucket_tooltip(&activity_bucket))
        .build();
    bar_area.set_draw_func(
        move |drawn_area, drawing_context, area_width, area_height| {
            let baseline = f64::from(area_height) - 1.0;
            let bars_left = (f64::from(area_width) - (2.0 * BAR_WIDTH + BAR_GAP)) / 2.0;
            draw_bar(
                drawing_context,
                bars_left,
                activity_bucket.scan_count,
                largest_value,
                SCAN_BAR_COLOR,
                baseline,
            );
            draw_bar(
                drawing_context,
                bars_left + BAR_WIDTH + BAR_GAP,
                activity_bucket.threat_count,
                largest_value,
                THREAT_BAR_COLOR,
                baseline,
            );
            let axis_color = drawn_area.color();
            drawing_context.set_source_rgba(
                f64::from(axis_color.red()),
                f64::from(axis_color.green()),
                f64::from(axis_color.blue()),
                0.2,
            );
            drawing_context.rectangle(0.0, baseline, f64::from(area_width), 1.0);
            let _surface_error_reported_by_gtk = drawing_context.fill();
        },
    );
    let date_label = gtk::Label::builder()
        .label(if shows_label {
            bucket_date_label(&activity_bucket)
        } else {
            String::new()
        })
        .css_classes(["caption", "dim-label"])
        .build();
    let column_box = gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(4)
        .hexpand(true)
        .homogeneous(false)
        .build();
    column_box.append(&bar_area);
    column_box.append(&date_label);
    column_box
}

pub fn replace_chart_columns(chart_box: &gtk::Box, activity_buckets: &[ScanActivityBucket]) {
    while let Some(existing_column) = chart_box.first_child() {
        chart_box.remove(&existing_column);
    }
    let largest_value = activity_buckets
        .iter()
        .map(|activity_bucket| activity_bucket.scan_count.max(activity_bucket.threat_count))
        .max()
        .unwrap_or(0)
        .max(1);
    let label_stride = (activity_buckets.len() / 6).max(1);
    (0..activity_buckets.len()).for_each(|bucket_position| {
        chart_box.append(&bucket_column(
            activity_buckets[bucket_position],
            largest_value,
            bucket_position % label_stride == 0,
        ));
    });
}

fn legend_swatch(swatch_color: ChartColor) -> gtk::DrawingArea {
    let swatch_area = gtk::DrawingArea::builder()
        .content_width(12)
        .content_height(12)
        .valign(gtk::Align::Center)
        .build();
    swatch_area.set_draw_func(
        move |_drawn_area, drawing_context, area_width, area_height| {
            drawing_context.set_source_rgb(swatch_color.red, swatch_color.green, swatch_color.blue);
            drawing_context.rectangle(0.0, 0.0, f64::from(area_width), f64::from(area_height));
            let _surface_error_reported_by_gtk = drawing_context.fill();
        },
    );
    swatch_area
}

pub fn chart_legend(scan_label: &str, threat_label: &str) -> gtk::Box {
    let legend_box = gtk::Box::builder()
        .spacing(6)
        .halign(gtk::Align::Center)
        .margin_bottom(12)
        .build();
    legend_box.append(&legend_swatch(SCAN_BAR_COLOR));
    legend_box.append(&gtk::Label::new(Some(scan_label)));
    let threat_swatch = legend_swatch(THREAT_BAR_COLOR);
    threat_swatch.set_margin_start(12);
    legend_box.append(&threat_swatch);
    legend_box.append(&gtk::Label::new(Some(threat_label)));
    legend_box
}
