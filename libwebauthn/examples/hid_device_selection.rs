use std::error::Error;

#[cfg(feature = "virtual-hid-device")]
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    // This example doesn't work for virtual devices, because
    // solo devices are not clone-able.
    Ok(())
}

#[cfg(not(feature = "virtual-hid-device"))]
#[tokio::main]
pub async fn main() -> Result<(), Box<dyn Error>> {
    use std::collections::HashMap;
    use std::time::Duration;

    use libwebauthn::transport::hid::channel::HidChannelHandle;
    use tracing_subscriber::{self, EnvFilter};

    use libwebauthn::transport::hid::{list_devices, HidDevice};
    use libwebauthn::transport::Device;

    fn setup_logging() {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .without_time()
            .init();
    }
    setup_logging();

    let devices = list_devices().await.unwrap();
    let mut expected_answers = devices.len();
    let (blinking_tx, mut blinking_rx) =
        tokio::sync::mpsc::channel::<Option<usize>>(expected_answers);
    let mut channel_map = HashMap::new();
    let (setup_tx, mut setup_rx) =
        tokio::sync::mpsc::channel::<(usize, HidDevice, HidChannelHandle)>(expected_answers);

    println!("Found {expected_answers} devices. Select one by touching.");
    for (idx, mut device) in devices.into_iter().enumerate() {
        let stx = setup_tx.clone();
        let btx = blinking_tx.clone();

        tokio::spawn(async move {
            let dev = device.clone();
            let mut channel = device.channel().await.unwrap();
            let handle = channel.get_handle();
            stx.send((idx, dev, handle)).await.unwrap();
            drop(stx);

            println!("Blinking {idx}");
            let res = channel
                .blink_and_wait_for_user_presence(Duration::from_secs(300))
                .await;
            match res {
                Ok(true) => {
                    println!("Touch from {idx}");
                    btx.send(Some(idx)).await.unwrap();
                }
                Ok(false) | Err(_) => {
                    btx.send(None).await.unwrap();
                }
            }
        });
    }
    drop(setup_tx);
    while let Some((idx, device, handle)) = setup_rx.recv().await {
        channel_map.insert(idx, (device, handle));
    }

    drop(blinking_tx);
    let mut found_one = false;
    while let Some(msg) = blinking_rx.recv().await {
        expected_answers -= 1;
        match msg {
            Some(idx) => {
                println!("Received {idx}");
                for (key, (_device, handle)) in channel_map.iter() {
                    if key == &idx {
                        continue;
                    }
                    println!("Cancelling {key}");
                    handle.cancel_ongoing_operation().await;
                }
                let (device, _handle) = &channel_map[&idx];
                println!("User chosen device: {device:?}");
                found_one = true;
            }
            None => {
                if expected_answers == 0 {
                    if found_one {
                        println!("All devices finished.");
                    } else {
                        println!("No device was chosen. All timed out.");
                    }
                    break;
                } else {
                    continue;
                }
            }
        }
    }

    Ok(())
}
