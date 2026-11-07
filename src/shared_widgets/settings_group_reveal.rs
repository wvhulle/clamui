use relm4::{
    gtk,
    gtk::{glib, graphene, prelude::*},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScrollAlignment {
    GroupAtTop,
}

pub trait ScrollGroupIntoView {
    fn scroll_group_into_view(&self, scroll_alignment: ScrollAlignment);
}

struct ScrolledGroupPosition {
    scrolled_window: gtk::ScrolledWindow,
    group_offset: f64,
}

fn scrolled_position_of(group_widget: &gtk::Widget) -> Option<ScrolledGroupPosition> {
    let scrolled_window = group_widget
        .ancestor(gtk::ScrolledWindow::static_type())?
        .downcast::<gtk::ScrolledWindow>()
        .ok()?;
    let scrolled_content = scrolled_window.child()?;
    let group_origin = group_widget.compute_point(&scrolled_content, &graphene::Point::zero())?;
    Some(ScrolledGroupPosition {
        scrolled_window,
        group_offset: f64::from(group_origin.y()),
    })
}

impl<GroupWidget: IsA<gtk::Widget>> ScrollGroupIntoView for GroupWidget {
    fn scroll_group_into_view(&self, scroll_alignment: ScrollAlignment) {
        let weak_group = self.upcast_ref::<gtk::Widget>().downgrade();
        glib::idle_add_local_once(move || {
            let Some(group_widget) = weak_group.upgrade() else {
                return;
            };
            let _focus_moved = group_widget.child_focus(gtk::DirectionType::TabForward);
            let Some(group_position) = scrolled_position_of(&group_widget) else {
                return;
            };
            match scroll_alignment {
                ScrollAlignment::GroupAtTop => group_position
                    .scrolled_window
                    .vadjustment()
                    .set_value(group_position.group_offset),
            }
        });
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupVisibility {
    GroupHidden,
    GroupMapped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContentReadiness {
    ContentLoading,
    ContentReady,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupReveal<RevealTarget> {
    NoRevealPending,
    RevealPending(RevealTarget),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SettingsGroupReveal<RevealTarget> {
    pending_reveal: GroupReveal<RevealTarget>,
    due_reveal: GroupReveal<RevealTarget>,
    group_visibility: GroupVisibility,
}

impl<RevealTarget: Copy + Eq> SettingsGroupReveal<RevealTarget> {
    pub const fn while_hidden() -> Self {
        Self {
            pending_reveal: GroupReveal::NoRevealPending,
            due_reveal: GroupReveal::NoRevealPending,
            group_visibility: GroupVisibility::GroupHidden,
        }
    }

    pub const fn begin_update(&mut self) {
        self.due_reveal = GroupReveal::NoRevealPending;
    }

    pub fn reveal_requested(
        &mut self,
        reveal_target: RevealTarget,
        content_readiness: ContentReadiness,
    ) {
        self.pending_reveal = GroupReveal::RevealPending(reveal_target);
        self.reveal_when_ready(content_readiness);
    }

    pub fn visibility_changed(
        &mut self,
        group_visibility: GroupVisibility,
        content_readiness: ContentReadiness,
    ) {
        self.group_visibility = group_visibility;
        self.reveal_when_ready(content_readiness);
    }

    pub fn reveal_when_ready(&mut self, content_readiness: ContentReadiness) {
        match (
            self.pending_reveal,
            self.group_visibility,
            content_readiness,
        ) {
            (
                GroupReveal::RevealPending(reveal_target),
                GroupVisibility::GroupMapped,
                ContentReadiness::ContentReady,
            ) => {
                self.due_reveal = GroupReveal::RevealPending(reveal_target);
                self.pending_reveal = GroupReveal::NoRevealPending;
            }
            (
                GroupReveal::RevealPending(_) | GroupReveal::NoRevealPending,
                GroupVisibility::GroupMapped | GroupVisibility::GroupHidden,
                ContentReadiness::ContentReady | ContentReadiness::ContentLoading,
            ) => {}
        }
    }

    pub fn reveals_now(&self, reveal_target: RevealTarget) -> bool {
        self.due_reveal == GroupReveal::RevealPending(reveal_target)
    }
}

#[cfg(test)]
mod settings_group_reveal_tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExampleGroup {
        FirstGroup,
        SecondGroup,
    }

    #[test]
    fn a_reveal_waits_until_the_group_is_mapped_and_its_content_ready() {
        let mut group_reveal = SettingsGroupReveal::while_hidden();
        group_reveal.reveal_requested(ExampleGroup::SecondGroup, ContentReadiness::ContentReady);
        assert!(!group_reveal.reveals_now(ExampleGroup::SecondGroup));
        group_reveal.begin_update();
        group_reveal.visibility_changed(
            GroupVisibility::GroupMapped,
            ContentReadiness::ContentLoading,
        );
        assert!(!group_reveal.reveals_now(ExampleGroup::SecondGroup));
        group_reveal.begin_update();
        group_reveal.reveal_when_ready(ContentReadiness::ContentReady);
        assert!(group_reveal.reveals_now(ExampleGroup::SecondGroup));
        assert!(!group_reveal.reveals_now(ExampleGroup::FirstGroup));
    }

    #[test]
    fn a_reveal_applies_once_and_later_updates_leave_the_scroll_alone() {
        let mut group_reveal = SettingsGroupReveal::while_hidden();
        group_reveal
            .visibility_changed(GroupVisibility::GroupMapped, ContentReadiness::ContentReady);
        group_reveal.reveal_requested(ExampleGroup::FirstGroup, ContentReadiness::ContentReady);
        assert!(group_reveal.reveals_now(ExampleGroup::FirstGroup));
        group_reveal.begin_update();
        group_reveal
            .visibility_changed(GroupVisibility::GroupHidden, ContentReadiness::ContentReady);
        group_reveal.begin_update();
        group_reveal
            .visibility_changed(GroupVisibility::GroupMapped, ContentReadiness::ContentReady);
        assert!(!group_reveal.reveals_now(ExampleGroup::FirstGroup));
    }
}
