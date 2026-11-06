use std::{os::unix::net::UnixStream, path::Path, thread, time::Duration};

use wayland_client::{
    Connection, Dispatch, EventQueue, QueueHandle, delegate_noop,
    globals::{GlobalListContents, registry_queue_init},
    protocol::{wl_pointer::ButtonState, wl_registry::WlRegistry},
};
use wayland_protocols_wlr::virtual_pointer::v1::client::{
    zwlr_virtual_pointer_manager_v1::ZwlrVirtualPointerManagerV1,
    zwlr_virtual_pointer_v1::ZwlrVirtualPointerV1,
};

use crate::scene_capture_failure::SceneCaptureFailure;

const LEFT_MOUSE_BUTTON: u32 = 0x110;
const POINTER_INPUT_DELAY: Duration = Duration::from_millis(250);
const EVENT_TIME_STEP_MILLISECONDS: u32 = 100;

#[derive(Clone, Copy)]
pub struct ScreenPosition {
    pub logical_x: u32,
    pub logical_y: u32,
}

#[derive(Clone, Copy)]
pub struct ScreenSize {
    pub logical_width: u32,
    pub logical_height: u32,
}

struct VirtualPointerEvents;

impl Dispatch<WlRegistry, GlobalListContents> for VirtualPointerEvents {
    fn event(
        _events: &mut Self,
        _registry: &WlRegistry,
        _registry_event: <WlRegistry as wayland_client::Proxy>::Event,
        _global_list: &GlobalListContents,
        _connection: &Connection,
        _queue_handle: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(VirtualPointerEvents: ignore ZwlrVirtualPointerManagerV1);
delegate_noop!(VirtualPointerEvents: ignore ZwlrVirtualPointerV1);

pub struct VirtualPointerInput {
    event_queue: EventQueue<VirtualPointerEvents>,
    virtual_pointer: ZwlrVirtualPointerV1,
    screen_size: ScreenSize,
    event_time_milliseconds: u32,
}

impl VirtualPointerInput {
    pub fn connect(
        wayland_socket: &Path,
        screen_size: ScreenSize,
    ) -> Result<Self, SceneCaptureFailure> {
        let wayland_connection = Connection::from_socket(UnixStream::connect(wayland_socket)?)?;
        let (compositor_globals, event_queue) =
            registry_queue_init::<VirtualPointerEvents>(&wayland_connection)?;
        let queue_handle = event_queue.handle();
        let pointer_manager: ZwlrVirtualPointerManagerV1 =
            compositor_globals.bind(&queue_handle, 1..=2, ())?;
        let virtual_pointer = pointer_manager.create_virtual_pointer(None, &queue_handle, ());
        let mut pointer_input = Self {
            event_queue,
            virtual_pointer,
            screen_size,
            event_time_milliseconds: 0,
        };
        pointer_input.deliver_pointer_frame()?;
        Ok(pointer_input)
    }

    fn next_event_time(&mut self) -> u32 {
        self.event_time_milliseconds += EVENT_TIME_STEP_MILLISECONDS;
        self.event_time_milliseconds
    }

    fn deliver_pointer_frame(&mut self) -> Result<(), SceneCaptureFailure> {
        self.virtual_pointer.frame();
        self.event_queue.roundtrip(&mut VirtualPointerEvents)?;
        thread::sleep(POINTER_INPUT_DELAY);
        Ok(())
    }

    pub fn move_to(&mut self, position: ScreenPosition) -> Result<(), SceneCaptureFailure> {
        let event_time = self.next_event_time();
        self.virtual_pointer.motion_absolute(
            event_time,
            position.logical_x,
            position.logical_y,
            self.screen_size.logical_width,
            self.screen_size.logical_height,
        );
        self.deliver_pointer_frame()
    }

    fn set_left_button(&mut self, button_state: ButtonState) -> Result<(), SceneCaptureFailure> {
        let event_time = self.next_event_time();
        self.virtual_pointer
            .button(event_time, LEFT_MOUSE_BUTTON, button_state);
        self.deliver_pointer_frame()
    }

    pub fn click_at(&mut self, position: ScreenPosition) -> Result<(), SceneCaptureFailure> {
        self.move_to(position)?;
        self.set_left_button(ButtonState::Pressed)?;
        self.set_left_button(ButtonState::Released)
    }
}
