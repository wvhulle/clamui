use std::path::PathBuf;

use gettextrs::gettext;
use relm4::{
    AsyncComponentSender, Component, ComponentController, Controller, adw,
    adw::prelude::*,
    gtk::glib,
    prelude::{AsyncComponent, AsyncComponentParts},
};

use crate::{
    file_quarantine::{
        quarantine_entries_page::{
            QuarantineEntriesPage, QuarantineEntriesPageInput, describe_quarantine_failure,
        },
        quarantine_entry_database::QuarantineVault,
        quarantine_file_moves::QuarantineMoveFailure,
    },
    malware_scan::scan_progress_page::{
        ScanProgressPage, ScanProgressPageInit, ScanProgressPageOutput,
    },
};

const APPLICATION_DATA_NAME: &str = "clamui";

enum ShellContent {
    VaultReady {
        _scan_page: Controller<ScanProgressPage>,
        _quarantine_page: Controller<QuarantineEntriesPage>,
    },
    VaultUnavailable,
}

pub struct ApplicationWindowShell {
    _shell_content: ShellContent,
}

fn application_data_directory() -> PathBuf {
    glib::user_data_dir().join(APPLICATION_DATA_NAME)
}

fn vault_unavailable_page(vault_failure: &QuarantineMoveFailure) -> adw::StatusPage {
    adw::StatusPage::builder()
        .icon_name("dialog-error-symbolic")
        .title(gettext("The quarantine database could not be opened"))
        .description(glib::markup_escape_text(&describe_quarantine_failure(
            vault_failure,
        )))
        .build()
}

fn application_pages(
    quarantine_vault: QuarantineVault,
    data_directory: PathBuf,
    window_root: &adw::ApplicationWindow,
) -> ShellContent {
    let quarantine_page = QuarantineEntriesPage::builder()
        .launch(quarantine_vault.clone())
        .detach();
    let quarantine_input_sender = quarantine_page.sender().clone();
    let scan_page = ScanProgressPage::builder()
        .launch(ScanProgressPageInit {
            quarantine_vault,
            file_list_directory: data_directory,
        })
        .connect_receiver(
            move |_scan_page_sender, scan_page_output| match scan_page_output {
                ScanProgressPageOutput::QuarantineEntriesChanged => {
                    quarantine_input_sender
                        .emit(QuarantineEntriesPageInput::ReloadEntriesRequested);
                }
            },
        );

    let page_stack = adw::ViewStack::new();
    page_stack.add_titled_with_icon(
        &**scan_page.widget(),
        Some("scan"),
        &gettext("Scan"),
        "system-search-symbolic",
    );
    page_stack.add_titled_with_icon(
        &**quarantine_page.widget(),
        Some("quarantine"),
        &gettext("Quarantine"),
        "security-high-symbolic",
    );
    let header_bar = adw::HeaderBar::builder()
        .title_widget(
            &adw::ViewSwitcher::builder()
                .stack(&page_stack)
                .policy(adw::ViewSwitcherPolicy::Wide)
                .build(),
        )
        .build();
    let toolbar_view = adw::ToolbarView::new();
    toolbar_view.add_top_bar(&header_bar);
    toolbar_view.set_content(Some(&page_stack));
    window_root.set_content(Some(&toolbar_view));
    ShellContent::VaultReady {
        _scan_page: scan_page,
        _quarantine_page: quarantine_page,
    }
}

impl AsyncComponent for ApplicationWindowShell {
    type Init = ();
    type Input = ();
    type Output = ();
    type CommandOutput = ();
    type Root = adw::ApplicationWindow;
    type Widgets = ();

    fn init_root() -> Self::Root {
        adw::ApplicationWindow::builder()
            .title("ClamUI")
            .width_request(360)
            .height_request(500)
            .default_width(800)
            .default_height(640)
            .build()
    }

    async fn init(
        _shell_init: Self::Init,
        root: Self::Root,
        _sender: AsyncComponentSender<Self>,
    ) -> AsyncComponentParts<Self> {
        let data_directory = application_data_directory();
        let opened_vault = QuarantineVault::open_vault(
            data_directory.join("quarantine.db"),
            data_directory.join("quarantine"),
        )
        .await;
        let shell_content = match opened_vault {
            Ok(quarantine_vault) => application_pages(quarantine_vault, data_directory, &root),
            Err(vault_failure) => {
                let unavailable_page = vault_unavailable_page(&vault_failure);
                let toolbar_view = adw::ToolbarView::new();
                toolbar_view.add_top_bar(&adw::HeaderBar::new());
                toolbar_view.set_content(Some(&unavailable_page));
                root.set_content(Some(&toolbar_view));
                ShellContent::VaultUnavailable
            }
        };
        AsyncComponentParts {
            model: Self {
                _shell_content: shell_content,
            },
            widgets: (),
        }
    }
}
