use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use crate::scene_capture_failure::SceneCaptureFailure;

const ENCODER_PROGRAM: &str = "img2webp";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnimationFrame {
    pub frame_path: PathBuf,
    pub shown_for: Duration,
}

pub fn encoder_arguments(
    animation_frames: &[AnimationFrame],
    animation_path: &Path,
) -> Vec<OsString> {
    ["-loop", "0", "-lossless"]
        .into_iter()
        .map(OsString::from)
        .chain(animation_frames.iter().flat_map(|animation_frame| {
            [
                OsString::from("-d"),
                OsString::from(animation_frame.shown_for.as_millis().to_string()),
                animation_frame.frame_path.clone().into_os_string(),
            ]
        }))
        .chain([OsString::from("-o"), animation_path.as_os_str().to_owned()])
        .collect()
}

pub fn encode_webp_animation(
    animation_frames: &[AnimationFrame],
    animation_path: &Path,
) -> Result<(), SceneCaptureFailure> {
    if animation_frames.is_empty() {
        return Err(SceneCaptureFailure::AnimationWithoutFrames {
            animation_path: animation_path.to_path_buf(),
        });
    }
    let exit_status = Command::new(ENCODER_PROGRAM)
        .args(encoder_arguments(animation_frames, animation_path))
        .status()
        .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
            tool_name: ENCODER_PROGRAM,
            start_failure,
        })?;
    if exit_status.success() {
        Ok(())
    } else {
        Err(SceneCaptureFailure::ToolFailed {
            tool_name: ENCODER_PROGRAM,
            exit_status,
        })
    }
}

#[cfg(test)]
mod webp_animation_encoding_tests {
    use super::*;

    #[test]
    fn every_frame_gets_its_own_duration_before_its_file() {
        let encoder_arguments = encoder_arguments(
            &[
                AnimationFrame {
                    frame_path: PathBuf::from("/frames/first.png"),
                    shown_for: Duration::from_millis(1800),
                },
                AnimationFrame {
                    frame_path: PathBuf::from("/frames/last.png"),
                    shown_for: Duration::from_secs(4),
                },
            ],
            Path::new("/out/scan.webp"),
        );
        assert_eq!(
            encoder_arguments,
            [
                "-loop",
                "0",
                "-lossless",
                "-d",
                "1800",
                "/frames/first.png",
                "-d",
                "4000",
                "/frames/last.png",
                "-o",
                "/out/scan.webp"
            ]
            .map(OsString::from)
        );
    }
}
