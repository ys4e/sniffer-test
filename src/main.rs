use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;
use pcap::Device;
use anyhow::{anyhow, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use log::info;
use ys_sniffer::{Config, PacketSource};

/// Write a file from a string.
/// file_path: The path to the file.
fn write_file<S: AsRef<str>>(file_path: S, content: String) -> std::io::Result<()> {
    let mut file = File::create(file_path.as_ref())?;
    file.write_all(content.as_bytes())?;
    Ok(())
}

/// Returns the opposite of the source.
fn opposite(source: PacketSource) -> PacketSource {
    match source {
        PacketSource::Client => PacketSource::Server,
        PacketSource::Server => PacketSource::Client
    }
}

struct CaptureDevice(Device);

impl CaptureDevice {
    /// Converts a list of devices into a list of capture devices.
    pub fn into(devices: &Vec<Device>) -> Vec<CaptureDevice> {
        devices
            .into_iter()
            .map(|d| CaptureDevice(d.clone()))
            .collect()
    }
}

impl Display for CaptureDevice {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let description = match self.0.desc {
            Some(ref desc) => desc,
            None => "No description"
        };

        write!(f, "{} - ({})", description, self.0.name)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the logger.
    if !std::env::var("RUST_LOG").is_ok() {
        std::env::set_var("RUST_LOG", "debug");
    }
    pretty_env_logger::init();

    // Get all devices for packet capturing.
    let device_list = Device::list()?;
    let device_names = CaptureDevice::into(&device_list);

    let device = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select a network device to capture from")
        .default(0)
        .items(&device_names)
        .interact()?;
    let device = device_list[device].name.clone();

    // Create the configuration for the sniffer.
    let options = Config {
        device_name: Some(device),
        ..Default::default()
    };

    // Create the channel for receiving packets.
    let (tx, rx) = crossbeam_channel::unbounded();

    // Start the packet sniffer.
    let Ok(shutdown_hook) = ys_sniffer::sniff(options, tx).await else {
        return Err(anyhow!("failed to start the sniffer"));
    };

    // Write all packets to the disk.
    tokio::spawn(async move {
        while let Ok(packet) = rx.recv() {
            let identifier = packet.id;
            let encoded = BASE64_STANDARD.encode(&packet.data);

            info!(
                "{:?} -> {:?}: {} of length {} bytes",
                packet.source,
                opposite(packet.source),
                identifier,
                packet.data.len()
            );

            write_file(format!("dump/packet-{identifier}.bin"), encoded).unwrap();
        }
    });

    info!("waiting for packets...");

    // Wait for a Ctrl + C signal.
    tokio::signal::ctrl_c().await?;
    
    info!("shutting down...");

    shutdown_hook.send(())?;

    Ok(())
}
