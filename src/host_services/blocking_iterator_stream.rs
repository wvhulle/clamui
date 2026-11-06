use std::{io, thread};

use futures::{SinkExt, Stream, channel::mpsc, executor::block_on, future::Either, stream};

const ITEM_BUFFER_SIZE: usize = 64;

pub fn blocking_iterator_stream<Item, ProducedItems>(
    thread_name: &str,
    produce_items: impl FnOnce() -> ProducedItems + Send + 'static,
    spawn_failure_item: impl FnOnce(io::Error) -> Item,
) -> impl Stream<Item = Item> + Send + 'static
where
    Item: Send + 'static,
    ProducedItems: Iterator<Item = Item>,
{
    let (mut item_sender, item_receiver) = mpsc::channel(ITEM_BUFFER_SIZE);
    let spawn_outcome = thread::Builder::new()
        .name(thread_name.to_owned())
        .spawn(move || {
            let _stream_dropped = produce_items()
                .try_for_each(|produced_item| block_on(item_sender.send(produced_item)));
        });
    match spawn_outcome {
        Ok(_producer_thread) => Either::Left(item_receiver),
        Err(spawn_failure) => Either::Right(stream::iter([spawn_failure_item(spawn_failure)])),
    }
}

#[cfg(test)]
mod blocking_iterator_stream_tests {
    use std::{
        sync::mpsc::{Receiver, sync_channel},
        time::Duration,
    };

    use futures::StreamExt;

    use super::*;

    #[tokio::test]
    async fn every_item_arrives_in_order() {
        let streamed_items = blocking_iterator_stream("ordered-items", || 0..200_u32, |_| u32::MAX)
            .collect::<Vec<_>>()
            .await;
        assert_eq!(streamed_items, (0..200).collect::<Vec<_>>());
    }

    fn produced_count_after(produced_counts: &Receiver<u32>) -> u32 {
        std::iter::from_fn(|| {
            produced_counts
                .recv_timeout(Duration::from_millis(500))
                .ok()
        })
        .last()
        .unwrap_or_default()
    }

    #[tokio::test]
    async fn dropping_the_stream_stops_the_producer() {
        let (count_sender, produced_counts) = sync_channel(1024);
        let mut endless_items = Box::pin(blocking_iterator_stream(
            "endless-items",
            move || {
                (0_u32..).inspect(move |produced_count| {
                    let _test_finished = count_sender.try_send(*produced_count);
                })
            },
            |_| u32::MAX,
        ));
        assert_eq!(endless_items.next().await, Some(0));
        drop(endless_items);
        let stopped_count = produced_count_after(&produced_counts);
        assert!(stopped_count < (ITEM_BUFFER_SIZE as u32) * 4);
        assert!(
            produced_counts
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
    }
}
