use std::future::Future;

use relm4::{Component, ComponentSender};

pub fn run_command_to_completion<Page>(
    sender: &ComponentSender<Page>,
    finished_command: impl Future<Output = Page::CommandOutput> + Send + 'static,
) where
    Page: Component,
    Page::CommandOutput: Send,
{
    sender.command(
        move |command_output, _shutdown_never_interrupts_the_work| async move {
            command_output.emit(finished_command.await);
        },
    );
}
