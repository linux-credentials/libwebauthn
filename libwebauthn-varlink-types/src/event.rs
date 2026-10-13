use libwebauthn::{
    transport::cable::channel::{CableUpdate, CableUxUpdate},
    UvUpdate,
};
use serde::{Deserialize, Serialize};
use zlink::introspect;

use crate::{VarlinkError, VarlinkPinNotSet, VarlinkPinRequired, VarlinkRetry};

/// What an [`Event`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, introspect::CustomType)]
#[zlink(rename = "EventKind")]
pub enum EventKind {
    /// Waiting for the user to scan the QR code or confirm on the device.
    ProximityCheck,
    Connecting,
    Authenticating,
    /// The channel is connected. Ends `AwaitConnecting`.
    Connected,
    /// The user must touch or otherwise confirm on the authenticator.
    PresenceRequired,
    /// User verification failed and may be retried. See `retry`.
    Retry,
    /// Answer with `ProvidePin`. See `pin_required` and `pin_token`.
    PinRequired,
    /// The authenticator needs a PIN to be set first. Answer with
    /// `ProvidePin`. See `pin_not_set` and `pin_token`.
    PinNotSet,
    /// The ceremony finished. See `response_json`.
    Completed,
}

/// Progress/result event streamed back to the client while a channel is
/// being established or a WebAuthn ceremony is running. Only the fields its
/// `kind` names are set.
#[derive(Debug, Clone, Serialize, Deserialize, introspect::Type)]
pub struct Event {
    pub kind: EventKind,

    /// The token to pass to `ProvidePin`, for
    /// `PinRequired` and `PinNotSet`.
    pub pin_token: Option<String>,
    pub pin_required: Option<VarlinkPinRequired>,
    pub pin_not_set: Option<VarlinkPinNotSet>,
    pub retry: Option<VarlinkRetry>,
    /// The response in WebAuthn IDL JSON, for `Completed`.
    pub response_json: Option<String>,
}

impl Event {
    /// An event that carries nothing beyond its `kind`.
    pub fn new(kind: EventKind) -> Self {
        Self {
            kind,
            pin_token: None,
            pin_required: None,
            pin_not_set: None,
            retry: None,
            response_json: None,
        }
    }
}

impl TryFrom<CableUxUpdate> for Event {
    type Error = VarlinkError;

    fn try_from(update: CableUxUpdate) -> Result<Self, Self::Error> {
        let kind = match update {
            CableUxUpdate::UvUpdate(UvUpdate::PinRequired(update)) => {
                return Ok(new_pin_required_event(update));
            }
            CableUxUpdate::UvUpdate(UvUpdate::PinNotSet(update)) => {
                return Ok(new_pin_not_set_event(update));
            }
            CableUxUpdate::UvUpdate(UvUpdate::UvRetry { attempts_left }) => {
                return Ok(Event {
                    retry: Some(attempts_left.into()),
                    ..Event::new(EventKind::Retry)
                });
            }
            CableUxUpdate::CableUpdate(CableUpdate::Error(err)) => return Err(err.into()),
            CableUxUpdate::UvUpdate(UvUpdate::PresenceRequired) => EventKind::PresenceRequired,
            CableUxUpdate::CableUpdate(CableUpdate::ProximityCheck) => EventKind::ProximityCheck,
            CableUxUpdate::CableUpdate(CableUpdate::Connecting) => EventKind::Connecting,
            CableUxUpdate::CableUpdate(CableUpdate::Authenticating) => EventKind::Authenticating,
            CableUxUpdate::CableUpdate(CableUpdate::Connected) => EventKind::Connected,
        };
        Ok(Event::new(kind))
    }
}

/// Builds the `PinRequired` event for a `UvUpdate::PinRequired`. The caller
/// sets `pin_token` to the token the update is parked under in the service's
/// `pending_pins` map.
pub fn new_pin_required_event<T>(into: T) -> Event
where
    T: Into<VarlinkPinRequired>,
{
    Event {
        pin_required: Some(into.into()),
        ..Event::new(EventKind::PinRequired)
    }
}

/// Builds the `PinNotSet` event for a `UvUpdate::PinNotSet`. The caller sets
/// `pin_token` to the token the update is parked under in the service's
/// `pending_pins` map.
pub fn new_pin_not_set_event<T>(into: T) -> Event
where
    T: Into<VarlinkPinNotSet>,
{
    Event {
        pin_not_set: Some(into.into()),
        ..Event::new(EventKind::PinNotSet)
    }
}

pub fn new_completed_event(response_json: String) -> Event {
    Event {
        response_json: Some(response_json),
        ..Event::new(EventKind::Completed)
    }
}

#[cfg(test)]
mod tests {
    use libwebauthn::transport::cable::error::CableError;

    use super::*;

    fn event(update: CableUxUpdate) -> Event {
        Event::try_from(update).unwrap()
    }

    #[test]
    fn uv_updates_become_events() {
        let presence = event(CableUxUpdate::UvUpdate(UvUpdate::PresenceRequired));
        assert_eq!(presence.kind, EventKind::PresenceRequired);

        let retry = event(CableUxUpdate::UvUpdate(UvUpdate::UvRetry {
            attempts_left: Some(2),
        }));
        assert_eq!(retry.kind, EventKind::Retry);
        assert_eq!(retry.retry.unwrap().attempts_left, Some(2));
    }

    #[test]
    fn cable_updates_become_events() {
        let cases = [
            (CableUpdate::ProximityCheck, EventKind::ProximityCheck),
            (CableUpdate::Connecting, EventKind::Connecting),
            (CableUpdate::Authenticating, EventKind::Authenticating),
            (CableUpdate::Connected, EventKind::Connected),
        ];
        for (update, kind) in cases {
            let event = event(CableUxUpdate::CableUpdate(update));
            assert_eq!(event.kind, kind);
            assert!(event.pin_token.is_none());
        }
    }

    #[test]
    fn cable_error_update_becomes_an_error() {
        let result = Event::try_from(CableUxUpdate::CableUpdate(CableUpdate::Error(
            CableError::ConnectionLost,
        )));
        assert!(matches!(result, Err(VarlinkError::TransportError { .. })));
    }

    #[test]
    fn completed_event_carries_the_response() {
        let event = new_completed_event("{}".into());
        assert_eq!(event.kind, EventKind::Completed);
        assert_eq!(event.response_json.as_deref(), Some("{}"));
    }

    #[test]
    fn kinds_serialize_as_their_names() {
        let json = serde_json::to_string(&Event::new(EventKind::PresenceRequired)).unwrap();
        assert!(json.contains(r#""kind":"PresenceRequired""#), "{json}");
    }
}
