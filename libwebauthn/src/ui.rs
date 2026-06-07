use std::collections::HashMap;
use std::error::Error;
use std::time::Duration;

use dbus::arg;
use dbus::arg::{RefArg, Variant};
use dbus::blocking::Connection;
use dbus::blocking::Proxy;
use dbus::Message;
use tracing::debug;
use uuid::Uuid;

#[derive(Debug)]
struct NotificationAction {
    pub id: String,
    pub action: String,
    pub parameter: Vec<arg::Variant<Box<dyn arg::RefArg + 'static>>>,
}

impl arg::AppendAll for NotificationAction {
    fn append(&self, i: &mut arg::IterAppend) {
        arg::RefArg::append(&self.id, i);
        arg::RefArg::append(&self.action, i);
        arg::RefArg::append(&self.parameter, i);
    }
}

impl arg::ReadAll for NotificationAction {
    fn read(i: &mut arg::Iter) -> Result<Self, arg::TypeMismatchError> {
        Ok(NotificationAction {
            id: i.read()?,
            action: i.read()?,
            parameter: i.read()?,
        })
    }
}

impl dbus::message::SignalArgs for NotificationAction {
    const NAME: &'static str = "ActionInvoked";
    const INTERFACE: &'static str = "org.freedesktop.portal.Notification";
}

fn variant_str(string: &str) -> Variant<Box<dyn RefArg>> {
    let s = String::from(string);
    let b = Box::new(s) as Box<dyn RefArg>;
    Variant(b)
}

pub enum CancellationResponse {
    UserCancel,
}

pub trait UI {
    type Handle;

    fn confirm_u2f_usb_register(
        &self,
        app_id: &str,
        timeout: Duration,
        callback: fn(CancellationResponse) -> (),
    ) -> Result<Self::Handle, Box<dyn Error>>;

    fn confirm_u2f_usb_sign(
        &self,
        app_id: &str,
        timeout: Duration,
        callback: fn(CancellationResponse) -> (),
    ) -> Result<Self::Handle, Box<dyn Error>>;

    fn cancel(&self, handle: Self::Handle) -> Result<(), Box<dyn Error>>;
}

pub struct NotificationPortalUI<'conn> {
    dbus_proxy: Proxy<'conn, &'conn Connection>,
}

pub struct NotificationHandle {
    id: String,
}

impl NotificationHandle {
    fn new(id: &str) -> NotificationHandle {
        NotificationHandle {
            id: String::from(id),
        }
    }
}

impl<'conn> NotificationPortalUI<'conn> {
    pub fn new(conn: &'conn Connection) -> Self {
        let proxy: Proxy<&'conn Connection> = conn.with_proxy(
            "org.freedesktop.portal.Desktop",  // iface
            "/org/freedesktop/portal/desktop", // object
            Duration::from_millis(5000),
        );
        Self { dbus_proxy: proxy }
    }

    fn _action(
        &self,
        title: &str,
        body: &str,
        callback: fn(CancellationResponse) -> (),
    ) -> Result<NotificationHandle, Box<dyn std::error::Error>> {
        let notification_id = Uuid::new_v4().to_hyphenated().to_string();

        let mut button1 = HashMap::new();
        button1.insert(String::from("action"), variant_str("cancel"));
        button1.insert(String::from("label"), variant_str("Cancel"));
        let buttons = vec![button1];

        let mut options = HashMap::new();
        options.insert("title", variant_str(title));
        options.insert("body", variant_str(body));
        options.insert("priority", variant_str("urgent"));
        options.insert("icon", variant_str("dialog-password")); // https://developer.gnome.org/icon-naming-spec/

        options.insert("default-action", variant_str("cancel"));
        options.insert("buttons", Variant(Box::new(buttons) as Box<dyn RefArg>));

        self.dbus_proxy.match_signal(
            move |h: NotificationAction, _: &Connection, _: &Message| {
                debug!(?h, "Received signal");
                match h.action.as_str() {
                    _ => callback(CancellationResponse::UserCancel),
                };
                true
            },
        )?;

        self.dbus_proxy.method_call(
            "org.freedesktop.portal.Notification",
            "AddNotification",
            (&notification_id, options),
        )?;

        Ok(NotificationHandle::new(&notification_id))
    }
}

impl<'conn> UI for NotificationPortalUI<'conn> {
    type Handle = NotificationHandle;

    fn confirm_u2f_usb_register(
        &self,
        app_id: &str,
        timeout: Duration,
        callback: fn(CancellationResponse) -> (),
    ) -> Result<Self::Handle, Box<dyn Error>> {
        self._action(
            "Touch your Security Key to register it",
            &format!(
                "\nThe application (<b>{}</b>) would like to register your FIDO U2F security key.\n\n\
                 Touch it within {:?}, or click Cancel.",
                app_id, timeout
            ),
            callback,
        )
    }

    fn confirm_u2f_usb_sign(
        &self,
        app_id: &str,
        timeout: Duration,
        callback: fn(CancellationResponse) -> (),
    ) -> Result<Self::Handle, Box<dyn Error>> {
        self._action(
            "Touch your Security Key to verify your identity ",
            &format!(
                "\nThe application (<b>{}</b>) would like to verify your\
                 identity using your FIDO U2F security key.\n\n\
                 Touch it within {:?}, or click Cancel.",
                app_id, timeout
            ),
            callback,
        )
    }

    fn cancel(&self, handle: Self::Handle) -> Result<(), Box<dyn Error>> {
        self.dbus_proxy.method_call(
            "org.freedesktop.portal.Notification",
            "RemoveNotification",
            (handle.id,),
        )?;
        Ok(())
    }
}
