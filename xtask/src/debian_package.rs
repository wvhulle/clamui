use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use crate::{
    metainfo_release_stamp::{APPLICATION_ID, stamp_metainfo_for_ci_release},
    release_publishing::{regular_files_sorted, released_package_version},
    task_failure::TaskFailure,
    tool_commands::{run_tool, tool_stdout},
};

const BUILD_TOOL_PACKAGES: [&str; 11] = [
    "rustup",
    "build-essential",
    "dpkg-dev",
    "pkg-config",
    "ca-certificates",
    "gettext",
    "libgtk-4-dev",
    "libadwaita-1-dev",
    "libsystemd-dev",
    "libglib2.0-dev",
    "libglib2.0-bin",
];
const PACKAGE_NAME: &str = "lazaret";
const PACKAGING_DIRECTORY: &str = "target/debian-package";
const LICENSE_PATH: &str = "LICENSE";
const SHLIBS_DEPENDS_PREFIX: &str = "shlibs:Depends=";
const APPLICATION_BINARY: &str = "usr/bin/lazaret";
const CLAMAV_ADMIN_BINARY: &str = "usr/libexec/lazaret/lazaret-clamav-admin";
const TUNABLE_SETTINGS_CONFFILE: &str = "/etc/lazaret/tunable-settings";
const COMPILED_SCHEMAS_PATH: &str = "/usr/share/glib-2.0/schemas/gschemas.compiled";
const BASE_CLAMD_CONFIG_PATH: &str = "/etc/clamav/clamd.conf";
const MERGED_CLAMD_CONFIG_PATH: &str = "/run/lazaret/clamd.conf";
const RUNTIME_DEPENDENCIES: &str =
    "clamav, dconf-gsettings-backend | gsettings-backend, hicolor-icon-theme";
const RECOMMENDED_PACKAGES: &str = "clamav-daemon, clamdscan, clamav-freshclam, polkitd";
const INSTALLED_ADMIN_SERVICE_FILES: [&str; 6] = [
    "/usr/share/polkit-1/actions/page.codeberg.wvhulle.Lazaret.policy",
    "/usr/share/dbus-1/system.d/page.codeberg.wvhulle.Lazaret.ClamavAdmin.conf",
    "/usr/share/dbus-1/system-services/page.codeberg.wvhulle.Lazaret.ClamavAdmin.service",
    "/usr/lib/systemd/system/lazaret-clamav-admin.service",
    "/usr/lib/systemd/system/lazaret-settings-merge.service",
    "/usr/lib/systemd/user/lazaret.service",
];
const POSTINST_SCRIPT: &str = "#!/bin/sh\nset -e\nif [ -d /run/systemd/system ]; then\n  \
                               systemctl daemon-reload || true\n  systemctl reload dbus.service \
                               || true\nfi\n";

struct DebianControlFields<'fields> {
    version: &'fields str,
    architecture: &'fields str,
    shared_library_dependencies: &'fields str,
    installed_size_kib: u64,
}

fn debian_control_text(control_fields: &DebianControlFields<'_>) -> String {
    let DebianControlFields {
        version,
        architecture,
        shared_library_dependencies,
        installed_size_kib,
    } = control_fields;
    format!(
        "Package: {PACKAGE_NAME}\nVersion: {version}\nArchitecture: {architecture}\nMaintainer: \
         Willem Vanhulle <willemvanhulle@gmail.com>\nInstalled-Size: \
         {installed_size_kib}\nDepends: {shared_library_dependencies}, \
         {RUNTIME_DEPENDENCIES}\nRecommends: {RECOMMENDED_PACKAGES}\nSection: utils\nPriority: \
         optional\nHomepage: https://codeberg.org/wvhulle/lazaret\nDescription: Desktop \
         front-end for the ClamAV installed on your system\n Scans files and folders with clamd \
         or clamscan, moves detections into a\n quarantine, raises alerts for detections of the \
         background services and\n schedules scans with systemd timers.\n"
    )
}

fn shared_library_dependencies(shlibdeps_output: &str) -> Option<&str> {
    shlibdeps_output
        .lines()
        .find_map(|output_line| output_line.strip_prefix(SHLIBS_DEPENDS_PREFIX))
        .filter(|dependency_list| !dependency_list.is_empty())
}

fn detect_shared_library_dependencies(packaging_directory: &Path) -> Result<String, TaskFailure> {
    let placeholder_directory = packaging_directory.join("debian");
    fs::create_dir_all(&placeholder_directory)?;
    fs::write(placeholder_directory.join("control"), "")?;
    let shlibdeps_output = tool_stdout(
        "dpkg-shlibdeps",
        Command::new("dpkg-shlibdeps")
            .arg("-O")
            .arg(Path::new("root").join(APPLICATION_BINARY))
            .arg(Path::new("root").join(CLAMAV_ADMIN_BINARY))
            .current_dir(packaging_directory),
    )?;
    shared_library_dependencies(&shlibdeps_output)
        .map(str::to_owned)
        .ok_or(TaskFailure::SharedLibraryDependenciesMissing)
}

fn tree_size_bytes(directory_path: &Path) -> Result<u64, TaskFailure> {
    fs::read_dir(directory_path)?.try_fold(0, |accumulated_bytes, directory_entry| {
        let entry_path = directory_entry?.path();
        let entry_bytes = if entry_path.is_dir() {
            tree_size_bytes(&entry_path)?
        } else {
            fs::symlink_metadata(&entry_path)?.len()
        };
        Ok(accumulated_bytes + entry_bytes)
    })
}

fn stage_installed_files(package_root: &Path) -> Result<(), TaskFailure> {
    if package_root.exists() {
        fs::remove_dir_all(package_root)?;
    }
    run_tool("make", Command::new("make").arg("build"))?;
    run_tool(
        "make",
        Command::new("make")
            .arg("install")
            .arg(format!("DESTDIR={}", package_root.display()))
            .args(["PREFIX=/usr", "SYSCONFDIR=/etc", "COMPILE_SCHEMAS=no"]),
    )?;
    let documentation_directory = package_root.join("usr/share/doc").join(PACKAGE_NAME);
    fs::create_dir_all(&documentation_directory)?;
    fs::copy(LICENSE_PATH, documentation_directory.join("copyright"))?;
    run_tool(
        "strip",
        Command::new("strip")
            .arg("--strip-unneeded")
            .arg(package_root.join(APPLICATION_BINARY))
            .arg(package_root.join(CLAMAV_ADMIN_BINARY)),
    )
}

fn write_control_files(
    package_root: &Path,
    control_fields: &DebianControlFields<'_>,
) -> Result<(), TaskFailure> {
    let control_directory = package_root.join("DEBIAN");
    fs::create_dir_all(&control_directory)?;
    fs::write(
        control_directory.join("control"),
        debian_control_text(control_fields),
    )?;
    fs::write(
        control_directory.join("conffiles"),
        format!("{TUNABLE_SETTINGS_CONFFILE}\n"),
    )?;
    let postinst_path = control_directory.join("postinst");
    fs::write(&postinst_path, POSTINST_SCRIPT)?;
    run_tool(
        "chmod",
        Command::new("chmod").arg("0755").arg(&postinst_path),
    )
}

fn debian_package_file_name(version: &str, architecture: &str) -> String {
    format!("{PACKAGE_NAME}_{version}_{architecture}.deb")
}

pub fn build_debian_package(output_directory: &Path) -> Result<(), TaskFailure> {
    stamp_metainfo_for_ci_release()?;
    let packaging_directory = PathBuf::from(PACKAGING_DIRECTORY);
    let package_root = packaging_directory.join("root");
    stage_installed_files(&package_root)?;
    let version = released_package_version()?;
    let architecture_output =
        tool_stdout("dpkg", Command::new("dpkg").arg("--print-architecture"))?;
    let architecture = architecture_output.trim();
    let shared_library_dependencies = detect_shared_library_dependencies(&packaging_directory)?;
    let installed_size_kib = tree_size_bytes(&package_root)?.div_ceil(1024);
    write_control_files(
        &package_root,
        &DebianControlFields {
            version: &version,
            architecture,
            shared_library_dependencies: &shared_library_dependencies,
            installed_size_kib,
        },
    )?;
    fs::create_dir_all(output_directory)?;
    run_tool(
        "dpkg-deb",
        Command::new("dpkg-deb")
            .args(["--root-owner-group", "--build"])
            .arg(&package_root)
            .arg(output_directory.join(debian_package_file_name(&version, architecture))),
    )
}

fn noninteractive_apt_get() -> Command {
    let mut apt_get_command = Command::new("apt-get");
    apt_get_command.env("DEBIAN_FRONTEND", "noninteractive");
    apt_get_command
}

fn update_package_lists() -> Result<(), TaskFailure> {
    run_tool("apt-get", noninteractive_apt_get().args(["update", "-qq"]))
}

pub fn ci_build_debian_package(output_directory: &Path) -> Result<(), TaskFailure> {
    update_package_lists()?;
    run_tool(
        "apt-get",
        noninteractive_apt_get()
            .args(["install", "-y", "-qq", "--no-install-recommends"])
            .args(BUILD_TOOL_PACKAGES),
    )?;
    build_debian_package(output_directory)
}

fn unresolved_shared_libraries(ldd_output: &str) -> Vec<&str> {
    ldd_output
        .lines()
        .filter(|ldd_line| ldd_line.contains("not found"))
        .map(str::trim)
        .collect()
}

fn compiled_schemas_contain_application(compiled_schemas: &[u8]) -> bool {
    compiled_schemas
        .windows(APPLICATION_ID.len())
        .any(|byte_window| byte_window == APPLICATION_ID.as_bytes())
}

fn built_package_paths(packages_directory: &Path) -> Result<Vec<PathBuf>, TaskFailure> {
    let package_paths = regular_files_sorted(packages_directory)?
        .into_iter()
        .filter(|file_path| file_path.extension().is_some_and(|suffix| suffix == "deb"))
        .map(fs::canonicalize)
        .collect::<Result<Vec<_>, _>>()?;
    if package_paths.is_empty() {
        return Err(TaskFailure::DebianPackageMissing {
            packages_directory: packages_directory.to_path_buf(),
        });
    }
    Ok(package_paths)
}

fn check_binary_libraries_resolve(binary_path: &Path) -> Result<(), TaskFailure> {
    let ldd_output = tool_stdout("ldd", Command::new("ldd").arg(binary_path))?;
    let unresolved_libraries = unresolved_shared_libraries(&ldd_output);
    if unresolved_libraries.is_empty() {
        Ok(())
    } else {
        Err(TaskFailure::SharedLibrariesUnresolved {
            library_lines: unresolved_libraries.join("; "),
        })
    }
}

fn check_merge_keeps_base_config() -> Result<(), TaskFailure> {
    fs::create_dir_all("/run/lazaret")?;
    run_tool(
        "lazaret-clamav-admin",
        Command::new(Path::new("/").join(CLAMAV_ADMIN_BINARY)).arg("merge"),
    )?;
    if fs::read(BASE_CLAMD_CONFIG_PATH)? == fs::read(MERGED_CLAMD_CONFIG_PATH)? {
        Ok(())
    } else {
        Err(TaskFailure::MergedConfigDiffers {
            base_config_path: BASE_CLAMD_CONFIG_PATH,
        })
    }
}

pub fn check_debian_package_install(packages_directory: &Path) -> Result<(), TaskFailure> {
    let package_paths = built_package_paths(packages_directory)?;
    update_package_lists()?;
    run_tool(
        "apt-get",
        noninteractive_apt_get()
            .args(["install", "-y", "-qq"])
            .args(&package_paths),
    )?;
    check_binary_libraries_resolve(&Path::new("/").join(APPLICATION_BINARY))?;
    check_binary_libraries_resolve(&Path::new("/").join(CLAMAV_ADMIN_BINARY))?;
    if !compiled_schemas_contain_application(&fs::read(COMPILED_SCHEMAS_PATH)?) {
        return Err(TaskFailure::CompiledSchemaMissing {
            application_id: APPLICATION_ID,
        });
    }
    if let Some(missing_file) = INSTALLED_ADMIN_SERVICE_FILES
        .iter()
        .find(|installed_file| !Path::new(installed_file).exists())
    {
        return Err(TaskFailure::InstalledFileMissing {
            installed_path: missing_file,
        });
    }
    check_merge_keeps_base_config()
}

#[cfg(test)]
mod debian_package_tests {
    use super::*;

    #[test]
    fn lists_only_unresolved_shared_libraries() {
        let ldd_output =
            "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x7f)\n\tlibgtk-4.so.1 => not found\n";
        assert_eq!(
            unresolved_shared_libraries(ldd_output),
            vec!["libgtk-4.so.1 => not found"]
        );
    }

    #[test]
    fn finds_application_id_inside_compiled_schemas() {
        let compiled_schemas =
            [b"\0\x01binary".as_slice(), APPLICATION_ID.as_bytes(), b"\0"].concat();
        assert!(compiled_schemas_contain_application(&compiled_schemas));
        assert!(!compiled_schemas_contain_application(b"org.gnome.other\0"));
    }

    #[test]
    fn reads_dependencies_from_shlibdeps_output() {
        assert_eq!(
            shared_library_dependencies("shlibs:Depends=libc6 (>= 2.38), libgtk-4-1 (>= 4.16.0)\n"),
            Some("libc6 (>= 2.38), libgtk-4-1 (>= 4.16.0)")
        );
        assert_eq!(shared_library_dependencies("misc:Depends=debconf\n"), None);
        assert_eq!(shared_library_dependencies("shlibs:Depends=\n"), None);
    }

    #[test]
    fn renders_control_fields_with_continuation_lines() {
        let control_text = debian_control_text(&DebianControlFields {
            version: "0.2.0",
            architecture: "amd64",
            shared_library_dependencies: "libc6 (>= 2.38)",
            installed_size_kib: 2048,
        });
        assert!(control_text.starts_with("Package: lazaret\nVersion: 0.2.0\n"));
        assert!(control_text.contains("\nInstalled-Size: 2048\n"));
        assert!(control_text.contains("\nDepends: libc6 (>= 2.38), clamav, "));
        assert!(control_text.ends_with("systemd timers.\n"));
        assert!(
            control_text
                .lines()
                .all(|control_line| control_line.contains(": ") || control_line.starts_with(' '))
        );
    }

    #[test]
    fn names_package_file_by_debian_convention() {
        assert_eq!(
            debian_package_file_name("0.2.0", "amd64"),
            "lazaret_0.2.0_amd64.deb"
        );
    }
}
