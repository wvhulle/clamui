use std::collections::VecDeque;

use atspi::{
    AccessibilityConnection, CoordType, ObjectRefOwned, Role, State,
    proxy::{
        accessible::{AccessibleProxy, ObjectRefExt},
        action::ActionProxy,
        bus::BusProxy,
        component::ComponentProxy,
    },
    zbus,
};

const SEARCHED_NODE_LIMIT: usize = 20_000;

#[derive(Debug, thiserror::Error)]
pub enum WidgetLookupFailure {
    #[error("the accessibility bus could not be reached: {0}")]
    BusUnreachable(#[from] atspi::AtspiError),
    #[error("an accessibility call failed: {0}")]
    CallFailed(#[from] zbus::Error),
    #[error("no visible {widget_role:?} named {accessible_name:?} was found")]
    WidgetMissing {
        widget_role: Role,
        accessible_name: String,
    },
    #[error("{accessible_name:?} offers no action to activate")]
    ActionMissing { accessible_name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SearchScope {
    WholeScreen,
    InsideWidget(Box<WidgetTarget>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WidgetTarget {
    pub widget_role: Role,
    pub accessible_name: String,
    pub search_scope: SearchScope,
}

pub use atspi::Role as WidgetRole;

impl WidgetTarget {
    pub fn new(widget_role: Role, accessible_name: impl Into<String>) -> Self {
        Self {
            widget_role,
            accessible_name: accessible_name.into(),
            search_scope: SearchScope::WholeScreen,
        }
    }

    pub fn inside(self, container_target: Self) -> Self {
        Self {
            search_scope: SearchScope::InsideWidget(Box::new(container_target)),
            ..self
        }
    }

    pub fn dialog(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::Dialog, accessible_name)
    }

    pub fn alert(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::Alert, accessible_name)
    }

    pub fn button(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::Button, accessible_name)
    }

    pub fn toggle_button(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::ToggleButton, accessible_name)
    }

    pub fn list_item(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::ListItem, accessible_name)
    }

    pub fn page_tab(accessible_name: impl Into<String>) -> Self {
        Self::new(Role::PageTab, accessible_name)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WidgetBounds {
    pub left_edge: i32,
    pub top_edge: i32,
    pub widget_width: i32,
    pub widget_height: i32,
}

impl WidgetBounds {
    pub const fn center_point(self) -> (i32, i32) {
        (
            self.left_edge + self.widget_width / 2,
            self.top_edge + self.widget_height / 2,
        )
    }
}

pub struct LocatedWidget {
    object_reference: ObjectRefOwned,
    pub widget_bounds: WidgetBounds,
}

pub struct AccessibleTree {
    accessibility_connection: AccessibilityConnection,
}

async fn proxy_for<'reference>(
    connection: &'reference zbus::Connection,
    object_reference: &'reference ObjectRefOwned,
) -> Result<AccessibleProxy<'reference>, WidgetLookupFailure> {
    Ok(object_reference.as_accessible_proxy(connection).await?)
}

async fn is_matching_widget(
    accessible_proxy: &AccessibleProxy<'_>,
    widget_target: &WidgetTarget,
) -> Result<bool, WidgetLookupFailure> {
    if accessible_proxy.get_role().await? != widget_target.widget_role {
        return Ok(false);
    }
    if accessible_proxy.name().await? != widget_target.accessible_name {
        return Ok(false);
    }
    Ok(accessible_proxy.get_state().await?.contains(State::Showing))
}

impl AccessibleTree {
    pub async fn connect_through(session_bus_address: &str) -> Result<Self, WidgetLookupFailure> {
        let session_bus = zbus::connection::Builder::address(session_bus_address)?
            .build()
            .await?;
        let accessibility_bus_address = BusProxy::new(&session_bus).await?.get_address().await?;
        Ok(Self {
            accessibility_connection: AccessibilityConnection::from_address(
                accessibility_bus_address.parse()?,
            )
            .await?,
        })
    }

    fn bus_connection(&self) -> &zbus::Connection {
        self.accessibility_connection.connection()
    }

    async fn top_level_nodes(&self) -> Result<Vec<ObjectRefOwned>, WidgetLookupFailure> {
        Ok(self
            .accessibility_connection
            .root_accessible_on_registry()
            .await?
            .get_children()
            .await?)
    }

    async fn search_from(
        &self,
        starting_nodes: Vec<ObjectRefOwned>,
        widget_target: &WidgetTarget,
    ) -> Option<ObjectRefOwned> {
        let mut pending_nodes = starting_nodes.into_iter().collect::<VecDeque<_>>();
        let mut searched_nodes = 0;
        while let Some(object_reference) = pending_nodes.pop_front() {
            searched_nodes += 1;
            if searched_nodes > SEARCHED_NODE_LIMIT || object_reference.is_null() {
                continue;
            }
            let Ok(accessible_proxy) = proxy_for(self.bus_connection(), &object_reference).await
            else {
                continue;
            };
            if is_matching_widget(&accessible_proxy, widget_target)
                .await
                .unwrap_or(false)
            {
                return Some(object_reference);
            }
            if let Ok(child_references) = accessible_proxy.get_children().await {
                pending_nodes.extend(child_references);
            }
        }
        None
    }

    async fn scope_nodes(
        &self,
        search_scope: &SearchScope,
    ) -> Result<Vec<ObjectRefOwned>, WidgetLookupFailure> {
        match search_scope {
            SearchScope::WholeScreen => self.top_level_nodes().await,
            SearchScope::InsideWidget(container_target) => {
                let container_reference = Box::pin(self.locate_reference(container_target)).await?;
                Ok(proxy_for(self.bus_connection(), &container_reference)
                    .await?
                    .get_children()
                    .await?)
            }
        }
    }

    async fn locate_reference(
        &self,
        widget_target: &WidgetTarget,
    ) -> Result<ObjectRefOwned, WidgetLookupFailure> {
        let starting_nodes = self.scope_nodes(&widget_target.search_scope).await?;
        self.search_from(starting_nodes, widget_target)
            .await
            .ok_or_else(|| WidgetLookupFailure::WidgetMissing {
                widget_role: widget_target.widget_role,
                accessible_name: widget_target.accessible_name.clone(),
            })
    }

    pub async fn find_widget(
        &self,
        widget_target: &WidgetTarget,
    ) -> Result<LocatedWidget, WidgetLookupFailure> {
        let object_reference = self.locate_reference(widget_target).await?;
        let widget_bounds = self.widget_bounds(&object_reference).await?;
        Ok(LocatedWidget {
            object_reference,
            widget_bounds,
        })
    }

    pub async fn describe_visible_widgets(&self) -> Result<Vec<String>, WidgetLookupFailure> {
        let mut pending_nodes = self
            .top_level_nodes()
            .await?
            .into_iter()
            .collect::<VecDeque<_>>();
        let mut widget_descriptions = Vec::new();
        let mut searched_nodes = 0;
        while let Some(object_reference) = pending_nodes.pop_front() {
            searched_nodes += 1;
            if searched_nodes > SEARCHED_NODE_LIMIT || object_reference.is_null() {
                continue;
            }
            let Ok(accessible_proxy) = proxy_for(self.bus_connection(), &object_reference).await
            else {
                continue;
            };
            let accessible_name = accessible_proxy.name().await.unwrap_or_default();
            let is_showing = accessible_proxy
                .get_state()
                .await
                .is_ok_and(|widget_state| widget_state.contains(State::Showing));
            if is_showing
                && !accessible_name.is_empty()
                && let Ok(widget_role) = accessible_proxy.get_role().await
            {
                widget_descriptions.push(format!("{widget_role:?} {accessible_name:?}"));
            }
            if let Ok(child_references) = accessible_proxy.get_children().await {
                pending_nodes.extend(child_references);
            }
        }
        Ok(widget_descriptions)
    }

    async fn widget_bounds(
        &self,
        object_reference: &ObjectRefOwned,
    ) -> Result<WidgetBounds, WidgetLookupFailure> {
        let component_proxy = ComponentProxy::builder(self.bus_connection())
            .destination(
                object_reference
                    .name()
                    .cloned()
                    .ok_or(atspi::AtspiError::MissingName)?,
            )?
            .path(object_reference.path().clone())?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?;
        let (left_edge, top_edge, widget_width, widget_height) =
            component_proxy.get_extents(CoordType::Window).await?;
        Ok(WidgetBounds {
            left_edge,
            top_edge,
            widget_width,
            widget_height,
        })
    }

    pub async fn activate_widget(
        &self,
        located_widget: &LocatedWidget,
        widget_target: &WidgetTarget,
    ) -> Result<(), WidgetLookupFailure> {
        let object_reference = &located_widget.object_reference;
        let action_proxy = ActionProxy::builder(self.bus_connection())
            .destination(
                object_reference
                    .name()
                    .cloned()
                    .ok_or(atspi::AtspiError::MissingName)?,
            )?
            .path(object_reference.path().clone())?
            .cache_properties(zbus::proxy::CacheProperties::No)
            .build()
            .await?;
        if action_proxy.n_actions().await.unwrap_or(0) == 0 || !action_proxy.do_action(0).await? {
            return Err(WidgetLookupFailure::ActionMissing {
                accessible_name: widget_target.accessible_name.clone(),
            });
        }
        Ok(())
    }
}
