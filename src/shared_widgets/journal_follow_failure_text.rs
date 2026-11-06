use gettextrs::gettext;

use crate::host_services::detection_journal::detection_journal_follower::JournalFollowFailure;

pub fn journal_follow_failure_text(follow_failure: &JournalFollowFailure) -> String {
    let failure_reason = match follow_failure {
        JournalFollowFailure::JournalReadFailed { read_failure_kind } => {
            read_failure_kind.to_string()
        }
        JournalFollowFailure::EntryTimestampInvalid => {
            gettext("a journal entry has a timestamp outside the supported range")
        }
        JournalFollowFailure::ReaderThreadFailed { spawn_failure_kind } => {
            gettext("the journal reader could not start: {error}")
                .replace("{error}", &spawn_failure_kind.to_string())
        }
    };
    gettext("Reading the system journal stopped: {error}").replace("{error}", &failure_reason)
}
