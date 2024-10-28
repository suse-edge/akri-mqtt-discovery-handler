use std::time::Duration;

use akri_discovery_utils::discovery::v0::Device;
use log::info;
use rumqttc::v5::ConnectionError;
use tokio::{
    sync::mpsc::{self, Sender},
    task::JoinHandle,
    time::timeout,
};

#[derive(Debug)]
pub enum Action {
    Add(String),
    Delete(String),
    Err(ConnectionError),
}

pub struct TimedDevice {
    pub device: Device,
    task: JoinHandle<()>,
    sender: Sender<()>,
}

impl TimedDevice {
    pub fn new(device: Device, delete_sender: Sender<Action>, timeout_duration: Duration) -> Self {
        let (sender, receiver) = mpsc::channel(1);
        let topic_clone = device.id.clone();
        let task = tokio::spawn(async move {
            let mut local_receiver = receiver;
            loop {
                if let Ok(Some(_)) = timeout(timeout_duration, local_receiver.recv()).await {
                    continue;
                }
                info!("Device {} timed out", topic_clone.clone());
                delete_sender
                    .send(Action::Delete(topic_clone.clone()))
                    .await
                    .unwrap();
                break;
            }
        });
        TimedDevice {
            device,
            task,
            sender,
        }
    }

    pub fn abort(&self) {
        self.task.abort()
    }

    pub async fn refresh(&self) -> Result<(), mpsc::error::SendError<()>> {
        self.sender.send(()).await
    }
}
