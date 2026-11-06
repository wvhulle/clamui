use std::{io, path::PathBuf, process::ExitStatus};

#[derive(Debug, thiserror::Error)]
pub enum TaskFailure {
    #[error("{0}")]
    SceneCaptureFailed(#[from] gtk_scene_capture::scene_capture_failure::SceneCaptureFailure),
    #[error("the fixture systemd service failed: {0}")]
    FixtureSystemdFailed(#[from] zbus::Error),
    #[error("environment variable {variable_name} is not set")]
    VariableMissing { variable_name: &'static str },
    #[error("an interaction had no effect: {expected_effect}")]
    InteractionHadNoEffect { expected_effect: &'static str },
    #[error("file operation failed: {0}")]
    FileOperationFailed(#[from] io::Error),
    #[error("{tool_name} could not be started: {start_failure}")]
    ToolNotStarted {
        tool_name: &'static str,
        start_failure: io::Error,
    },
    #[error("no [package] version in {manifest_path}")]
    PackageVersionMissing { manifest_path: &'static str },
    #[error("no <release> entry in {metainfo_path}")]
    MetainfoReleaseMissing { metainfo_path: &'static str },
    #[error("dpkg-shlibdeps reported no dependencies")]
    SharedLibraryDependenciesMissing,
    #[error("no .deb file in {}", packages_directory.display())]
    DebianPackageMissing { packages_directory: PathBuf },
    #[error("unresolved shared libraries: {library_lines}")]
    SharedLibrariesUnresolved { library_lines: String },
    #[error("{application_id} is not in the compiled schemas")]
    CompiledSchemaMissing { application_id: &'static str },
    #[error("the package did not install {installed_path}")]
    InstalledFileMissing { installed_path: &'static str },
    #[error("merging without runtime changes altered {base_config_path}")]
    MergedConfigDiffers { base_config_path: &'static str },
    #[error("{tool_name} failed with {exit_status}")]
    ToolFailed {
        tool_name: &'static str,
        exit_status: ExitStatus,
    },
}
