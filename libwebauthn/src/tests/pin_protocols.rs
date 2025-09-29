use std::time::Duration;

use crate::pin::PinManagement;
use crate::proto::ctap2::Ctap2PinUvAuthProtocol;
use crate::transport::hid::get_virtual_device;
use crate::transport::{Channel, Device};
use crate::UvUpdate;
use test_log::test;
use tokio::sync::broadcast::error::TryRecvError;
use tokio::sync::broadcast::Receiver;

const TIMEOUT: Duration = Duration::from_secs(10);

async fn handle_updates(mut state_recv: Receiver<UvUpdate>) {
    let Ok(UvUpdate::PinRequired(p)) = state_recv.recv().await else {
        panic!("Did not receive PinRequired UvUpdate!");
    };
    p.send_pin("1234").expect("Failed to send first PIN");
}

#[test(tokio::test)]
async fn test_webauthn_change_pin_once() {
    let protos = [Ctap2PinUvAuthProtocol::One, Ctap2PinUvAuthProtocol::Two];
    for proto in protos {
        let mut device = get_virtual_device();
        let mut channel = device.channel().await.unwrap();

        let mut state_recv = channel.get_ux_update_receiver();

        channel.set_forced_pin_protocol(proto);

        channel
            .change_pin(String::from("1234"), TIMEOUT)
            .await
            .unwrap();

        assert_eq!(state_recv.try_recv(), Err(TryRecvError::Empty))
    }
}

#[test(tokio::test)]
async fn test_webauthn_change_pin_twice() {
    let protos = [Ctap2PinUvAuthProtocol::One, Ctap2PinUvAuthProtocol::Two];
    for proto in protos {
        let mut device = get_virtual_device();
        let mut channel = device.channel().await.unwrap();

        let state_recv = channel.get_ux_update_receiver();
        let update_handle = tokio::spawn(handle_updates(state_recv));

        channel.set_forced_pin_protocol(proto);

        channel
            .change_pin(String::from("1234"), TIMEOUT)
            .await
            .unwrap();

        channel
            .change_pin(String::from("4321"), TIMEOUT)
            .await
            .unwrap();

        // Keeping the update-recv alive until the end to check all updates
        update_handle.await.unwrap();
    }
}
