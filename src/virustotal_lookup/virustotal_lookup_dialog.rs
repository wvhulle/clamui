use std::{path::PathBuf, sync::Arc};

use bytesize::ByteSize;
use gettextrs::{gettext, ngettext};
use relm4::{Component, ComponentParts, ComponentSender, adw, adw::prelude::*, gtk};
use tokio::task::spawn_blocking;

use crate::{
    malware_scan::scanner_output_parser::sanitize_scanner_line,
    virustotal_lookup::{
        pinned_scan_file::{PinnedFileFailure, PinnedScanFile},
        virustotal_api_client::{
            DetectionCategory, FileReportLookup, MAXIMUM_UPLOAD_BYTES, VirusTotalClient,
            VirusTotalFailure, VirusTotalReport,
        },
        virustotal_key_storage::read_stored_api_key,
        virustotal_preferences_page::describe_key_failure,
    },
};

const MANUAL_UPLOAD_URL: &str = "https://www.virustotal.com/gui/home/upload";

enum LookupProgress {
    CheckingFile,
    ApiKeyMissing,
    UploadingFile,
    ReportReady(VirusTotalReport),
    LookupFailed { failure_text: String },
}

pub struct VirusTotalLookupDialog {
    file_path: PathBuf,
    lookup_progress: LookupProgress,
}

#[derive(Debug)]
pub enum VirusTotalLookupDialogInput {
    UploadConfirmed {
        lookup_client: VirusTotalClient,
        confirmed_file: Arc<PinnedScanFile>,
    },
    UploadDeclined,
    OpenReportRequested,
    OpenManualUploadRequested,
}

#[derive(Debug)]
pub enum VirusTotalLookupDialogCommand {
    ApiKeyMissing,
    LookupStopped {
        failure_text: String,
    },
    ReportReceived(VirusTotalReport),
    UploadConsentNeeded {
        lookup_client: VirusTotalClient,
        pinned_file: Arc<PinnedScanFile>,
    },
}

impl std::fmt::Debug for VirusTotalClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VirusTotalClient")
    }
}

fn describe_api_failure(api_failure: &VirusTotalFailure) -> String {
    match api_failure {
        VirusTotalFailure::ApiKeyRejected => gettext("VirusTotal rejected the API key."),
        VirusTotalFailure::RequestLimitReached => {
            gettext("The VirusTotal request limit was reached. Try again later.")
        }
        VirusTotalFailure::FileTooLarge => gettext("File too large"),
        VirusTotalFailure::AnalysisTimedOut => gettext(
            "VirusTotal has the file but did not finish analyzing it in time. Check back later.",
        ),
        VirusTotalFailure::FileChangedAfterConfirmation => {
            gettext("The file changed after you confirmed, so it was not uploaded.")
        }
        other_failure => other_failure.to_string(),
    }
}

fn describe_pin_failure(pin_failure: &PinnedFileFailure) -> String {
    match pin_failure {
        PinnedFileFailure::NotRegularFile => gettext("Path is not a regular file"),
        PinnedFileFailure::FileUnreadable(read_failure) => {
            gettext("Cannot read file: {error}").replace("{error}", &read_failure.to_string())
        }
    }
}

async fn check_file_against_virustotal(file_path: PathBuf) -> VirusTotalLookupDialogCommand {
    let stored_key = match read_stored_api_key().await {
        Ok(Some(stored_key)) => stored_key,
        Ok(None) => return VirusTotalLookupDialogCommand::ApiKeyMissing,
        Err(key_failure) => {
            return VirusTotalLookupDialogCommand::LookupStopped {
                failure_text: describe_key_failure(&key_failure),
            };
        }
    };
    let pinned_file = match spawn_blocking(move || PinnedScanFile::open_and_hash(&file_path)).await
    {
        Ok(Ok(pinned_file)) => Arc::new(pinned_file),
        Ok(Err(pin_failure)) => {
            return VirusTotalLookupDialogCommand::LookupStopped {
                failure_text: describe_pin_failure(&pin_failure),
            };
        }
        Err(interrupted_task) => {
            return VirusTotalLookupDialogCommand::LookupStopped {
                failure_text: interrupted_task.to_string(),
            };
        }
    };
    let lookup_client = match VirusTotalClient::with_api_key(stored_key) {
        Ok(lookup_client) => lookup_client,
        Err(client_failure) => {
            return VirusTotalLookupDialogCommand::LookupStopped {
                failure_text: describe_api_failure(&client_failure),
            };
        }
    };
    match lookup_client
        .look_up_file_report(&pinned_file.content_hash)
        .await
    {
        Ok(FileReportLookup::ReportAvailable(file_report)) => {
            VirusTotalLookupDialogCommand::ReportReceived(file_report)
        }
        Ok(FileReportLookup::FileUnknownToVirusTotal) => {
            VirusTotalLookupDialogCommand::UploadConsentNeeded {
                lookup_client,
                pinned_file,
            }
        }
        Err(lookup_failure) => VirusTotalLookupDialogCommand::LookupStopped {
            failure_text: describe_api_failure(&lookup_failure),
        },
    }
}

fn request_upload_consent(
    lookup_client: VirusTotalClient,
    pinned_file: Arc<PinnedScanFile>,
    root: &adw::Dialog,
    sender: &ComponentSender<VirusTotalLookupDialog>,
) {
    let consent_body = gettext(
        "VirusTotal does not know this file yet.\n\n{path}\n{size}\n\nUploading shares its \
         contents with VirusTotal and its security partners, and other users may be able to \
         download them. Only upload files you are authorized to share, and never files with \
         personal or confidential data.",
    )
    .replace("{size}", &ByteSize::b(pinned_file.file_size).to_string())
    .replace(
        "{path}",
        &sanitize_scanner_line(&pinned_file.file_path.to_string_lossy()),
    );
    let consent_dialog =
        adw::AlertDialog::new(Some(&gettext("Upload to VirusTotal?")), Some(&consent_body));
    consent_dialog.add_response("cancel", &gettext("Cancel"));
    consent_dialog.add_response("upload", &gettext("Upload File"));
    consent_dialog.set_response_appearance("upload", adw::ResponseAppearance::Destructive);
    consent_dialog.set_default_response(Some("cancel"));
    consent_dialog.set_close_response("cancel");
    let input_sender = sender.input_sender().clone();
    consent_dialog.connect_response(None, move |_dialog, consent_response| {
        if consent_response == "upload" {
            input_sender.emit(VirusTotalLookupDialogInput::UploadConfirmed {
                lookup_client: lookup_client.clone(),
                confirmed_file: Arc::clone(&pinned_file),
            });
        } else {
            input_sender.emit(VirusTotalLookupDialogInput::UploadDeclined);
        }
    });
    consent_dialog.present(Some(root));
}

impl VirusTotalLookupDialog {
    fn status_title(&self) -> String {
        match &self.lookup_progress {
            LookupProgress::CheckingFile => gettext("Checking the file's hash…"),
            LookupProgress::ApiKeyMissing => gettext("Not configured"),
            LookupProgress::UploadingFile => gettext("Uploading and waiting for the analysis…"),
            LookupProgress::ReportReady(file_report) if file_report.detecting_engine_count > 0 => {
                ngettext(
                    "{count} engine detected a threat",
                    "{count} engines detected a threat",
                    u32::try_from(file_report.detecting_engine_count).unwrap_or(u32::MAX),
                )
                .replace("{count}", &file_report.detecting_engine_count.to_string())
            }
            LookupProgress::ReportReady(_clean_report) => gettext("No engines detected a threat"),
            LookupProgress::LookupFailed { .. } => gettext("The lookup failed"),
        }
    }

    fn status_details(&self) -> String {
        match &self.lookup_progress {
            LookupProgress::ApiKeyMissing => gettext(
                "Add an API key in Preferences, or open VirusTotal's upload page to send the file \
                 yourself.",
            ),
            LookupProgress::ReportReady(file_report) => format!(
                "{}/{} · SHA-256 {}",
                file_report.detecting_engine_count,
                file_report.total_engine_count,
                file_report.content_hash
            ),
            LookupProgress::LookupFailed { failure_text } => failure_text.clone(),
            LookupProgress::CheckingFile | LookupProgress::UploadingFile => String::new(),
        }
    }

    fn detection_lines(&self) -> String {
        let LookupProgress::ReportReady(file_report) = &self.lookup_progress else {
            return String::new();
        };
        file_report
            .engine_detections
            .iter()
            .map(|engine_detection| {
                let category_text = match engine_detection.detection_category {
                    DetectionCategory::Malicious => gettext("Malicious"),
                    DetectionCategory::Suspicious => gettext("Suspicious"),
                };
                format!(
                    "{}: {} ({category_text})",
                    sanitize_scanner_line(&engine_detection.engine_name),
                    sanitize_scanner_line(&engine_detection.detection_name),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn lookup_is_running(&self) -> bool {
        matches!(
            self.lookup_progress,
            LookupProgress::CheckingFile | LookupProgress::UploadingFile
        )
    }
}

fn open_external_url(external_url: &str, root: &adw::Dialog) {
    gtk::UriLauncher::new(external_url).launch(
        root.root().and_downcast::<gtk::Window>().as_ref(),
        relm4::gtk::gio::Cancellable::NONE,
        |_launch_outcome| {},
    );
}

#[relm4::component(pub)]
impl Component for VirusTotalLookupDialog {
    type Init = PathBuf;
    type Input = VirusTotalLookupDialogInput;
    type Output = ();
    type CommandOutput = VirusTotalLookupDialogCommand;

    view! {
        adw::Dialog {
            set_title: &gettext("VirusTotal Scan"),
            set_content_width: 520,
            set_content_height: 420,

            #[wrap(Some)]
            set_child = &adw::ToolbarView {
                add_top_bar = &adw::HeaderBar {},

                #[wrap(Some)]
                set_content = &gtk::ScrolledWindow {
                    set_hscrollbar_policy: gtk::PolicyType::Never,

                    adw::Clamp {
                        set_margin_top: 12,
                        set_margin_bottom: 24,
                        set_margin_start: 12,
                        set_margin_end: 12,

                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_spacing: 12,

                            gtk::Label {
                                set_xalign: 0.0,
                                set_wrap: true,
                                set_wrap_mode: gtk::pango::WrapMode::WordChar,
                                add_css_class: "dim-label",
                                set_label: &sanitize_scanner_line(&model.file_path.to_string_lossy()),
                            },

                            gtk::Spinner {
                                #[watch]
                                set_visible: model.lookup_is_running(),
                                #[watch]
                                set_spinning: model.lookup_is_running(),
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_wrap: true,
                                add_css_class: "title-3",
                                #[watch]
                                set_label: &model.status_title(),
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_wrap: true,
                                set_wrap_mode: gtk::pango::WrapMode::WordChar,
                                set_selectable: true,
                                #[watch]
                                set_label: &model.status_details(),
                            },

                            gtk::Label {
                                set_xalign: 0.0,
                                set_wrap: true,
                                set_wrap_mode: gtk::pango::WrapMode::WordChar,
                                set_selectable: true,
                                add_css_class: "monospace",
                                #[watch]
                                set_label: &model.detection_lines(),
                            },

                            gtk::Button {
                                set_label: &gettext("View on VirusTotal"),
                                set_halign: gtk::Align::Center,
                                #[watch]
                                set_visible: matches!(model.lookup_progress, LookupProgress::ReportReady(_)),
                                connect_clicked => VirusTotalLookupDialogInput::OpenReportRequested,
                            },

                            gtk::Button {
                                set_label: &gettext("Open VirusTotal website"),
                                set_halign: gtk::Align::Center,
                                #[watch]
                                set_visible: matches!(model.lookup_progress, LookupProgress::ApiKeyMissing),
                                connect_clicked => VirusTotalLookupDialogInput::OpenManualUploadRequested,
                            },
                        },
                    },
                },
            },
        }
    }

    fn init(
        file_path: PathBuf,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let model = Self {
            file_path: file_path.clone(),
            lookup_progress: LookupProgress::CheckingFile,
        };
        let widgets = view_output!();
        sender.oneshot_command(check_file_against_virustotal(file_path));
        ComponentParts { model, widgets }
    }

    fn update(
        &mut self,
        dialog_input: VirusTotalLookupDialogInput,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match dialog_input {
            VirusTotalLookupDialogInput::UploadConfirmed {
                lookup_client,
                confirmed_file,
            } => {
                self.lookup_progress = LookupProgress::UploadingFile;
                sender.oneshot_command(async move {
                    match lookup_client.upload_confirmed_file(&confirmed_file).await {
                        Ok(file_report) => {
                            VirusTotalLookupDialogCommand::ReportReceived(file_report)
                        }
                        Err(upload_failure) => VirusTotalLookupDialogCommand::LookupStopped {
                            failure_text: describe_api_failure(&upload_failure),
                        },
                    }
                });
            }
            VirusTotalLookupDialogInput::UploadDeclined => {
                self.lookup_progress = LookupProgress::LookupFailed {
                    failure_text: gettext(
                        "VirusTotal does not know this file, and it was not uploaded.",
                    ),
                };
            }
            VirusTotalLookupDialogInput::OpenReportRequested => {
                if let LookupProgress::ReportReady(file_report) = &self.lookup_progress {
                    open_external_url(&file_report.report_url, root);
                }
            }
            VirusTotalLookupDialogInput::OpenManualUploadRequested => {
                open_external_url(MANUAL_UPLOAD_URL, root);
            }
        }
    }

    fn update_cmd(
        &mut self,
        dialog_command: VirusTotalLookupDialogCommand,
        sender: ComponentSender<Self>,
        root: &Self::Root,
    ) {
        match dialog_command {
            VirusTotalLookupDialogCommand::ApiKeyMissing => {
                self.lookup_progress = LookupProgress::ApiKeyMissing;
            }
            VirusTotalLookupDialogCommand::LookupStopped { failure_text } => {
                self.lookup_progress = LookupProgress::LookupFailed { failure_text };
            }
            VirusTotalLookupDialogCommand::ReportReceived(file_report) => {
                self.lookup_progress = LookupProgress::ReportReady(file_report);
            }
            VirusTotalLookupDialogCommand::UploadConsentNeeded {
                lookup_client,
                pinned_file,
            } => {
                if pinned_file.file_size > MAXIMUM_UPLOAD_BYTES {
                    self.lookup_progress = LookupProgress::LookupFailed {
                        failure_text: gettext("File too large"),
                    };
                } else {
                    request_upload_consent(lookup_client, pinned_file, root, &sender);
                }
            }
        }
    }
}
