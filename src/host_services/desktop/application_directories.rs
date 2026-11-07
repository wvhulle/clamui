use std::path::PathBuf;

use relm4::gtk::glib;
use xdg::BaseDirectories;

use crate::APPLICATION_DATA_NAME;

fn application_base_directories() -> BaseDirectories {
    BaseDirectories::with_prefix(APPLICATION_DATA_NAME)
}

pub fn application_data_directory() -> PathBuf {
    application_base_directories()
        .get_data_home()
        .unwrap_or_else(|| glib::user_data_dir().join(APPLICATION_DATA_NAME))
}

pub fn application_config_directory() -> PathBuf {
    application_base_directories()
        .get_config_home()
        .unwrap_or_else(|| glib::user_config_dir().join(APPLICATION_DATA_NAME))
}

#[cfg(test)]
mod application_directories_tests {
    use super::*;

    #[test]
    fn data_and_config_folders_are_named_after_the_build() {
        assert!(application_data_directory().ends_with(APPLICATION_DATA_NAME));
        assert!(application_config_directory().ends_with(APPLICATION_DATA_NAME));
        assert!(application_data_directory().is_absolute());
    }
}
