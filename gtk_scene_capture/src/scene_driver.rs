use std::{
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};

use crate::{
    accessible_widget_lookup::{AccessibleTree, LocatedWidget, WidgetLookupFailure, WidgetTarget},
    headless_sway_session::HeadlessSwaySession,
    scene_capture_failure::SceneCaptureFailure,
    virtual_pointer_input::{ScreenPosition, VirtualPointerInput},
};

const WIDGET_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const WIDGET_POLL_INTERVAL: Duration = Duration::from_millis(250);
const INTERACTION_SETTLE_DURATION: Duration = Duration::from_millis(1500);
const ACCESSIBILITY_BUS_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserInteraction {
    ClickWidget(WidgetTarget),
    HoverWidget(WidgetTarget),
    WaitForWidget(WidgetTarget),
    CaptureScreen { screenshot_name: &'static str },
}

pub struct SceneDriver<'session> {
    headless_session: &'session HeadlessSwaySession,
    async_runtime: tokio::runtime::Runtime,
    accessible_tree: AccessibleTree,
    pointer_input: VirtualPointerInput,
    output_directory: PathBuf,
}

fn screen_position_of(located_widget: &LocatedWidget) -> ScreenPosition {
    let (center_horizontal, center_vertical) = located_widget.widget_bounds.center_point();
    ScreenPosition {
        logical_x: center_horizontal.max(0).unsigned_abs(),
        logical_y: center_vertical.max(0).unsigned_abs(),
    }
}

impl<'session> SceneDriver<'session> {
    pub fn attach(
        headless_session: &'session HeadlessSwaySession,
        output_directory: &Path,
    ) -> Result<Self, SceneCaptureFailure> {
        let async_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let session_bus_address = headless_session.bus_address();
        let waiting_since = Instant::now();
        let accessible_tree = loop {
            match async_runtime.block_on(AccessibleTree::connect_through(&session_bus_address)) {
                Ok(accessible_tree) => break accessible_tree,
                Err(_bus_not_ready) if waiting_since.elapsed() < ACCESSIBILITY_BUS_TIMEOUT => {
                    thread::sleep(WIDGET_POLL_INTERVAL);
                }
                Err(_bus_never_ready) => {
                    return Err(SceneCaptureFailure::NeverReady {
                        awaited_condition: "the accessibility bus",
                    });
                }
            }
        };
        Ok(Self {
            headless_session,
            pointer_input: VirtualPointerInput::connect(
                &headless_session.wayland_socket_path(),
                headless_session.screen_size(),
            )?,
            async_runtime,
            accessible_tree,
            output_directory: output_directory.to_path_buf(),
        })
    }

    fn wait_for_widget(
        &self,
        widget_target: &WidgetTarget,
    ) -> Result<LocatedWidget, SceneCaptureFailure> {
        let waiting_since = Instant::now();
        loop {
            match self
                .async_runtime
                .block_on(self.accessible_tree.find_widget(widget_target))
            {
                Ok(located_widget) => return Ok(located_widget),
                Err(WidgetLookupFailure::WidgetMissing { .. })
                    if waiting_since.elapsed() < WIDGET_WAIT_TIMEOUT =>
                {
                    thread::sleep(WIDGET_POLL_INTERVAL);
                }
                Err(lookup_failure) => {
                    let visible_widgets = self
                        .async_runtime
                        .block_on(self.accessible_tree.describe_visible_widgets())
                        .unwrap_or_default();
                    eprintln!("visible widgets:\n{}", visible_widgets.join("\n"));
                    return Err(lookup_failure.into());
                }
            }
        }
    }

    fn click_widget(&mut self, widget_target: &WidgetTarget) -> Result<(), SceneCaptureFailure> {
        let located_widget = self.wait_for_widget(widget_target)?;
        let activation_outcome = self.async_runtime.block_on(
            self.accessible_tree
                .activate_widget(&located_widget, widget_target),
        );
        match activation_outcome {
            Ok(()) => Ok(()),
            Err(WidgetLookupFailure::ActionMissing { .. }) => self
                .pointer_input
                .click_at(screen_position_of(&located_widget)),
            Err(activation_failure) => Err(activation_failure.into()),
        }
    }

    fn hover_widget(&mut self, widget_target: &WidgetTarget) -> Result<(), SceneCaptureFailure> {
        let located_widget = self.wait_for_widget(widget_target)?;
        self.pointer_input
            .move_to(screen_position_of(&located_widget))
    }

    fn capture_screen(&self, screenshot_name: &str) -> Result<(), SceneCaptureFailure> {
        let exit_status = self
            .headless_session
            .session_command("grim")
            .arg(self.output_directory.join(format!("{screenshot_name}.png")))
            .status()
            .map_err(|start_failure| SceneCaptureFailure::ToolNotStarted {
                tool_name: "grim",
                start_failure,
            })?;
        if exit_status.success() {
            Ok(())
        } else {
            Err(SceneCaptureFailure::ToolFailed {
                tool_name: "grim",
                exit_status,
            })
        }
    }

    pub fn perform(
        &mut self,
        user_interaction: &UserInteraction,
    ) -> Result<(), SceneCaptureFailure> {
        match user_interaction {
            UserInteraction::ClickWidget(widget_target) => {
                self.click_widget(widget_target)?;
                thread::sleep(INTERACTION_SETTLE_DURATION);
            }
            UserInteraction::HoverWidget(widget_target) => {
                self.hover_widget(widget_target)?;
                thread::sleep(INTERACTION_SETTLE_DURATION);
            }
            UserInteraction::WaitForWidget(widget_target) => {
                self.wait_for_widget(widget_target)?;
            }
            UserInteraction::CaptureScreen { screenshot_name } => {
                self.capture_screen(screenshot_name)?;
            }
        }
        Ok(())
    }

    pub fn perform_all(
        &mut self,
        user_interactions: &[UserInteraction],
    ) -> Result<(), SceneCaptureFailure> {
        user_interactions
            .iter()
            .try_for_each(|user_interaction| self.perform(user_interaction))
    }
}
