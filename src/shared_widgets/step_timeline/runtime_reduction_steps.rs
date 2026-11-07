use gettextrs::{gettext, ngettext};

use crate::{
    host_services::{
        clamav_admin_service::live_settings_client::StoredOverridesFailure,
        desktop::locale_formatting::exact_local_time_text,
        protection_evidence::host_protection_evidence::{
            OverriddenSetting, OverridesChangeTime, OverridesReadFailure, ReducedSetting,
            RuntimeReductions,
        },
    },
    shared_widgets::step_timeline::{
        step_evidence_builders::{CheckedCondition, evidence_row, plain_rows},
        timeline_step_contents::{
            SettledStep, StepActionButton, StepActionSlot, StepEvidenceRow, TimelineStep,
        },
    },
};

const ON_ACCESS_KEY_PREFIX: &str = "OnAccess";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReducedSettingGroup {
    OnAccessSettings,
    EngineSettings,
}

impl ReducedSettingGroup {
    pub fn includes_setting(self, setting_key: &str) -> bool {
        let on_access_setting = setting_key.starts_with(ON_ACCESS_KEY_PREFIX);
        match self {
            Self::OnAccessSettings => on_access_setting,
            Self::EngineSettings => !on_access_setting,
        }
    }
}

fn reduced_settings_status(
    reduced_settings: &[&ReducedSetting],
    change_time: OverridesChangeTime,
) -> String {
    let setting_count = u32::try_from(reduced_settings.len()).unwrap_or(u32::MAX);
    match change_time {
        OverridesChangeTime::ChangedAt { changed_at } => ngettext(
            "{count} setting checks less than configured since {time}",
            "{count} settings check less than configured since {time}",
            setting_count,
        )
        .replace("{time}", &exact_local_time_text(changed_at)),
        OverridesChangeTime::ChangeTimeUnknown => ngettext(
            "{count} setting checks less than configured, since a time that could not be read",
            "{count} settings check less than configured, since a time that could not be read",
            setting_count,
        ),
    }
    .replace("{count}", &reduced_settings.len().to_string())
}

fn override_change_time_row(change_time: OverridesChangeTime) -> StepEvidenceRow {
    evidence_row(
        gettext("Changed"),
        match change_time {
            OverridesChangeTime::ChangedAt { changed_at } => exact_local_time_text(changed_at),
            OverridesChangeTime::ChangeTimeUnknown => gettext("Unknown"),
        },
    )
}

fn overrides_failure_text(read_failure: OverridesReadFailure) -> String {
    match read_failure {
        OverridesReadFailure::StoredOverridesUnusable(
            StoredOverridesFailure::OverridesFileUnreadable { failure_kind },
        ) => gettext(
            "Unknown whether settings were reduced, because the runtime changes could not be \
             read: {error}",
        )
        .replace("{error}", &failure_kind.to_string()),
        OverridesReadFailure::StoredOverridesUnusable(
            StoredOverridesFailure::OverridesFileInvalid,
        ) => gettext(
            "Unknown whether settings were reduced, because the runtime changes file is not in \
             the expected format. ClamAV runs with the system configuration until it is fixed.",
        ),
        OverridesReadFailure::ReadingTaskInterrupted => gettext(
            "Unknown whether settings were reduced, because reading the runtime changes stopped \
             before it finished",
        ),
    }
}

fn reduced_settings_in_group(
    reduced_settings: &[ReducedSetting],
    setting_group: ReducedSettingGroup,
) -> Vec<&ReducedSetting> {
    reduced_settings
        .iter()
        .filter(|reduced_setting| setting_group.includes_setting(&reduced_setting.setting_key))
        .collect()
}

fn overridden_settings_in_group(
    overridden_settings: &[OverriddenSetting],
    setting_group: ReducedSettingGroup,
) -> Vec<&OverriddenSetting> {
    overridden_settings
        .iter()
        .filter(|overridden_setting| {
            setting_group.includes_setting(&overridden_setting.setting_key)
        })
        .collect()
}

pub fn runtime_reduction_condition(
    runtime_reductions: &RuntimeReductions,
    setting_group: ReducedSettingGroup,
) -> CheckedCondition {
    match runtime_reductions {
        RuntimeReductions::NothingReduced => CheckedCondition::ConditionMet,
        RuntimeReductions::OverridesUnreadable(_) => CheckedCondition::EvidenceUnknown,
        RuntimeReductions::SettingsReduced {
            reduced_settings, ..
        } => {
            if reduced_settings_in_group(reduced_settings, setting_group).is_empty() {
                CheckedCondition::ConditionMet
            } else {
                CheckedCondition::ReviewSuggested
            }
        }
        RuntimeReductions::BaseConfigUnreadable {
            overridden_settings,
            ..
        } => {
            if overridden_settings_in_group(overridden_settings, setting_group).is_empty() {
                CheckedCondition::ConditionMet
            } else {
                CheckedCondition::EvidenceUnknown
            }
        }
    }
}

pub fn runtime_reduction_step<StepAction: StepActionButton>(
    runtime_reductions: &RuntimeReductions,
    setting_group: ReducedSettingGroup,
    header_action: StepActionSlot<StepAction>,
) -> Option<TimelineStep<StepAction>> {
    let node_state = runtime_reduction_condition(runtime_reductions, setting_group).node_state();
    match runtime_reductions {
        RuntimeReductions::NothingReduced => None,
        RuntimeReductions::OverridesUnreadable(read_failure) => Some(TimelineStep::settled(
            gettext("Settings changed at runtime"),
            gettext(
                "Someone with the administrator password can change ClamAV settings at runtime. \
                 Lazaret could not read those changes, so it can't tell whether they check less \
                 than your configuration does.",
            ),
            overrides_failure_text(*read_failure),
            SettledStep {
                header_action,
                ..SettledStep::without_offers(node_state)
            },
        )),
        RuntimeReductions::SettingsReduced {
            change_time,
            reduced_settings,
        } => {
            let grouped_settings = reduced_settings_in_group(reduced_settings, setting_group);
            (!grouped_settings.is_empty()).then(|| {
                TimelineStep::settled(
                    gettext("Protection reduced on purpose"),
                    gettext(
                        "Someone with the administrator password changed ClamAV settings at \
                         runtime in a way that checks less than your configuration does. The \
                         system changes of the page that owns the setting show who and when.",
                    ),
                    reduced_settings_status(&grouped_settings, *change_time),
                    SettledStep {
                        evidence_rows: plain_rows(grouped_settings.iter().map(|reduced_setting| {
                            evidence_row(
                                reduced_setting.setting_key.clone(),
                                gettext("{base} in your configuration, {changed} now")
                                    .replace("{base}", &reduced_setting.base_value)
                                    .replace("{changed}", &reduced_setting.changed_value),
                            )
                        })),
                        header_action,
                        ..SettledStep::without_offers(node_state)
                    },
                )
            })
        }
        RuntimeReductions::BaseConfigUnreadable {
            change_time,
            overridden_settings,
        } => {
            let grouped_settings = overridden_settings_in_group(overridden_settings, setting_group);
            (!grouped_settings.is_empty()).then(|| {
                TimelineStep::settled(
                    gettext("Settings changed at runtime"),
                    gettext(
                        "Someone with the administrator password changed ClamAV settings at \
                         runtime. Your clamd.conf could not be read, so Lazaret can't tell \
                         whether these changes check less than your configuration does. The \
                         system changes of the page that owns the setting show who and when.",
                    ),
                    gettext(
                        "Settings were changed at runtime, but clamd.conf could not be read to \
                         compare them",
                    ),
                    SettledStep {
                        evidence_rows: plain_rows(
                            grouped_settings
                                .iter()
                                .map(|overridden_setting| {
                                    evidence_row(
                                        overridden_setting.setting_key.clone(),
                                        gettext("{changed} now").replace(
                                            "{changed}",
                                            &overridden_setting.changed_value,
                                        ),
                                    )
                                })
                                .chain(std::iter::once(override_change_time_row(*change_time))),
                        ),
                        header_action,
                        ..SettledStep::without_offers(node_state)
                    },
                )
            })
        }
    }
}

#[cfg(test)]
mod runtime_reduction_steps_tests {
    use super::*;
    use crate::shared_widgets::step_timeline::timeline_step_contents::{
        ActionConsequence, OfferedAction, StepNodeState,
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ReviewStepAction {
        ReviewChangedSettings,
    }

    impl StepActionButton for ReviewStepAction {
        fn button_label(&self) -> String {
            match self {
                Self::ReviewChangedSettings => "Review".to_owned(),
            }
        }

        fn action_consequence(&self) -> ActionConsequence {
            match self {
                Self::ReviewChangedSettings => ActionConsequence::OrdinaryAction,
            }
        }
    }

    fn reduced_setting(setting_key: &str) -> ReducedSetting {
        ReducedSetting {
            setting_key: setting_key.to_owned(),
            base_value: "yes".to_owned(),
            changed_value: "no".to_owned(),
        }
    }

    fn mixed_reductions() -> RuntimeReductions {
        RuntimeReductions::SettingsReduced {
            change_time: OverridesChangeTime::ChangeTimeUnknown,
            reduced_settings: vec![
                reduced_setting("OnAccessPrevention"),
                reduced_setting("DetectPUA"),
            ],
        }
    }

    fn reduction_rows(setting_group: ReducedSettingGroup) -> Vec<String> {
        runtime_reduction_step::<ReviewStepAction>(
            &mixed_reductions(),
            setting_group,
            StepActionSlot::NoAction,
        )
        .map(|reduction_step| {
            reduction_step
                .shown_evidence_rows()
                .into_iter()
                .map(|step_evidence| step_evidence.evidence_name.clone())
                .collect()
        })
        .unwrap_or_default()
    }

    #[test]
    fn each_group_lists_only_its_own_reduced_keys() {
        assert_eq!(
            reduction_rows(ReducedSettingGroup::OnAccessSettings),
            vec!["OnAccessPrevention"]
        );
        assert_eq!(
            reduction_rows(ReducedSettingGroup::EngineSettings),
            vec!["DetectPUA"]
        );
    }

    #[test]
    fn a_group_without_reduced_keys_adds_no_step_and_stays_met() {
        let on_access_only = RuntimeReductions::SettingsReduced {
            change_time: OverridesChangeTime::ChangeTimeUnknown,
            reduced_settings: vec![reduced_setting("OnAccessPrevention")],
        };
        assert_eq!(
            runtime_reduction_step::<ReviewStepAction>(
                &on_access_only,
                ReducedSettingGroup::EngineSettings,
                StepActionSlot::NoAction,
            ),
            None
        );
        assert_eq!(
            runtime_reduction_condition(&on_access_only, ReducedSettingGroup::EngineSettings),
            CheckedCondition::ConditionMet
        );
    }

    #[test]
    fn unreadable_overrides_concern_every_group() {
        let unreadable_overrides =
            RuntimeReductions::OverridesUnreadable(OverridesReadFailure::ReadingTaskInterrupted);
        [
            ReducedSettingGroup::EngineSettings,
            ReducedSettingGroup::OnAccessSettings,
        ]
        .into_iter()
        .for_each(|setting_group| {
            let reduction_step = runtime_reduction_step(
                &unreadable_overrides,
                setting_group,
                StepActionSlot::ActionOffered(OfferedAction::plain(
                    ReviewStepAction::ReviewChangedSettings,
                )),
            )
            .unwrap();
            assert_eq!(reduction_step.node_state(), StepNodeState::NeedsReview);
            assert!(reduction_step.header_offer().is_some());
        });
    }
}
