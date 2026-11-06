use futures::{
    Stream, StreamExt,
    future::ready,
    stream::{self, AbortHandle},
};
use relm4::{Component, ComponentSender};

pub struct RunningStream(AbortHandle);

impl std::fmt::Debug for RunningStream {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RunningStream")
    }
}

impl RunningStream {
    pub fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for RunningStream {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn run_stream<Page>(
    sender: &ComponentSender<Page>,
    command_stream: impl Stream<Item = Page::CommandOutput> + Send + 'static,
) -> RunningStream
where
    Page: Component,
    Page::CommandOutput: Send,
{
    let (abortable_commands, abort_handle) = stream::abortable(command_stream);
    sender.command(move |command_output, shutdown| {
        shutdown
            .register(abortable_commands.for_each(move |page_command| {
                command_output.emit(page_command);
                ready(())
            }))
            .drop_on_shutdown()
    });
    RunningStream(abort_handle)
}

pub fn run_stream_then<Page>(
    sender: &ComponentSender<Page>,
    command_stream: impl Stream<Item = Page::CommandOutput> + Send + 'static,
    end_command: Page::CommandOutput,
) -> RunningStream
where
    Page: Component,
    Page::CommandOutput: Send,
{
    let (abortable_commands, abort_handle) = stream::abortable(command_stream);
    sender.command(move |command_output, shutdown| {
        shutdown
            .register(async move {
                abortable_commands
                    .for_each(|page_command| {
                        command_output.emit(page_command);
                        ready(())
                    })
                    .await;
                command_output.emit(end_command);
            })
            .drop_on_shutdown()
    });
    RunningStream(abort_handle)
}

pub fn run_stream_to_completion<Page>(
    sender: &ComponentSender<Page>,
    command_stream: impl Stream<Item = Page::CommandOutput> + Send + 'static,
) where
    Page: Component,
    Page::CommandOutput: Send,
{
    sender.command(move |command_output, _shutdown_never_interrupts_the_work| {
        command_stream.for_each(move |page_command| {
            command_output.emit(page_command);
            ready(())
        })
    });
}
