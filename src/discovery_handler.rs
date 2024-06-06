use std::{
    collections::HashMap,
    convert::{TryFrom, TryInto},
    time::Duration,
};

use akri_discovery_utils::discovery::{
    discovery_handler::{deserialize_discovery_details, DISCOVERED_DEVICES_CHANNEL_CAPACITY},
    v0::{
        discovery_handler_server::DiscoveryHandler, ByteData, Device, DiscoverRequest,
        DiscoverResponse,
    },
    DiscoverStream,
};
use async_trait::async_trait;
use log::{error, info, trace};
use regex::Regex;
use rumqttc::v5::{
    mqttbytes::v5::{Filter, Packet},
    AsyncClient, Event, MqttOptions,
};
use rustls::{Certificate, PrivateKey, RootCertStore};
use rustls_native_certs::load_native_certs;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tonic::{Response, Status};
use url::Url;

use super::discovery_impl::{Action, TimedDevice};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MqttDiscoveryDetails {
    pub mqtt_broker_uri: url::Url,
    pub topics: Vec<String>,
    pub timeout_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "serde_regex")]
    pub message_regexp: Option<Regex>,
    pub properties_prefix: Option<String>,
}

pub struct DiscoveryHandlerImpl {
    register_sender: tokio::sync::mpsc::Sender<()>,
}

impl DiscoveryHandlerImpl {
    pub fn new(register_sender: tokio::sync::mpsc::Sender<()>) -> Self {
        DiscoveryHandlerImpl { register_sender }
    }
}

fn fill_client_id_if_needed(mut url: Url) -> Url {
    let pairs = url.query_pairs();
    if pairs.filter(|(key, _)| key == "client_id").count() > 0 {
        return url;
    }
    url.query_pairs_mut().append_pair("client_id", "akri");
    url
}

fn invalid_arg(message: impl Into<String>) -> Status {
    tonic::Status::new(tonic::Code::InvalidArgument, message)
}

fn authenticate_mqtt(
    mqttoptions: &mut MqttOptions,
    properties: &HashMap<String, ByteData>,
) -> Result<(), Status> {
    if let Some(raw_username) = properties.get("mqtt_broker_username") {
        let raw_password = properties.get("mqtt_broker_password").ok_or(invalid_arg(
            "A username got specified, but no password given",
        ))?;
        let username = String::from_utf8(
            raw_username
                .clone()
                .vec
                .ok_or(invalid_arg("username is empty"))?,
        )
        .map_err(|e| invalid_arg(format!("unable to parse username: {}", e)))?;
        let password = String::from_utf8(
            raw_password
                .clone()
                .vec
                .ok_or(invalid_arg("password is empty"))?,
        )
        .map_err(|e| invalid_arg(format!("unable to parse password: {}", e)))?;
        if !username.is_empty() && !password.is_empty() {
            mqttoptions.set_credentials(username, password);
        } else {
            info!("No username or password provided -- skipping authentication")
        }
    }
    Ok(())
}

fn get_certificate_and_key(
    properties: &HashMap<String, ByteData>,
) -> Result<Option<(Vec<Certificate>, PrivateKey)>, Status> {
    if let Some(raw_certificate) = properties.get("mqtt_broker_certificate") {
        let raw_key = properties
            .get("mqtt_broker_key")
            .ok_or(invalid_arg("A certificate got specified, but no key given"))?
            .vec
            .as_ref()
            .ok_or(invalid_arg("A certificate got specified, but no key given"))?;
        // Allow key to be either PKCS8, EC key or RSA key
        let key_pem = PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut &raw_key[..])
                .map_err(|e| invalid_arg(format!("Cannot parse key: {}", e)))?
                .iter()
                .chain(
                    rustls_pemfile::ec_private_keys(&mut &raw_key[..])
                        .map_err(|e| invalid_arg(format!("Cannot parse key: {}", e)))?
                        .iter(),
                )
                .chain(
                    rustls_pemfile::rsa_private_keys(&mut &raw_key[..])
                        .map_err(|e| invalid_arg(format!("Cannot parse key: {}", e)))?
                        .iter(),
                )
                .next()
                .ok_or(invalid_arg("No key found"))?
                .clone(),
        );
        let certs_pem_raw = raw_certificate.vec.as_ref().unwrap().clone();
        let certificates_pem: Vec<Certificate> = rustls_pemfile::certs(&mut &certs_pem_raw[..])
            .map_err(|e| invalid_arg(format!("Unable to parse certs: {}", e)))?
            .into_iter()
            .map(Certificate)
            .collect();
        return Ok(Some((certificates_pem, key_pem)));
    }
    Ok(None)
}

fn setup_tls(
    mqttoptions: &mut MqttOptions,
    properties: &HashMap<String, ByteData>,
) -> Result<(), Status> {
    match mqttoptions.transport() {
        rumqttc::Transport::Tls(_) => {}
        _ => return Ok(()),
    }
    let mut root_cert_store = RootCertStore::empty();
    if let Some(raw_ca) = properties.get("mqtt_broker_ca") {
        let ca = rustls_pemfile::certs(
            &mut &raw_ca.vec.as_ref().ok_or(invalid_arg("CA key is empty"))?[..],
        )
        .map_err(|e| invalid_arg(format!("CA is invalid: {}", e)))?;
        root_cert_store.add_parsable_certificates(&ca[..]);
    } else {
        let root_certs = load_native_certs().unwrap();
        root_cert_store.add_parsable_certificates(&root_certs[..]);
    }
    let client_config_builder = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store);
    let client_config = match get_certificate_and_key(properties)? {
        None => client_config_builder.with_no_client_auth(),
        Some((cert, key)) => client_config_builder
            .with_client_auth_cert(cert, key)
            .map_err(|e| invalid_arg(format!("Invalid key: {}", e)))?,
    };
    mqttoptions.set_transport(rumqttc::Transport::Tls(client_config.into()));
    Ok(())
}

#[async_trait]
impl DiscoveryHandler for DiscoveryHandlerImpl {
    type DiscoverStream = DiscoverStream;
    async fn discover(
        &self,
        request: tonic::Request<DiscoverRequest>,
    ) -> Result<Response<Self::DiscoverStream>, Status> {
        info!("discover - called for mqtt protocol");
        let register_sender = self.register_sender.clone();
        let discover_request = request.get_ref();
        let (discovered_devices_sender, discovered_devices_receiver) =
            mpsc::channel(DISCOVERED_DEVICES_CHANNEL_CAPACITY);
        let discovery_handler_config: MqttDiscoveryDetails =
            deserialize_discovery_details(&discover_request.discovery_details)
                .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, format!("{}", e)))?;

        info!(
            "discover - mqtt_broker_uri: {}",
            discovery_handler_config.mqtt_broker_uri
        );
        info!("discover - topics: {:?}", discovery_handler_config.topics);
        info!(
            "discover - timeout_seconds: {}",
            discovery_handler_config.timeout_seconds
        );

        let mut mqttoptions = MqttOptions::try_from(fill_client_id_if_needed(
            discovery_handler_config.mqtt_broker_uri.clone(),
        ))
        .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, format!("{}", e)))?;
        authenticate_mqtt(&mut mqttoptions, &discover_request.discovery_properties)?;
        setup_tls(&mut mqttoptions, &discover_request.discovery_properties)?;

        let timeout_duration = Duration::from_secs(
            discovery_handler_config
                .timeout_seconds
                .try_into()
                .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, format!("{}", e)))?,
        );
        let (mqtt_client, mut mqtt_eventloop) = AsyncClient::new(mqttoptions, 10);
        mqtt_client
            .subscribe_many(
                discovery_handler_config
                    .topics
                    .iter()
                    .map(|topic| Filter::new(topic, rumqttc::v5::mqttbytes::QoS::AtMostOnce)),
            )
            .await
            .map_err(|e| tonic::Status::new(tonic::Code::InvalidArgument, format!("{}", e)))?;

        let (message_received_sender, mut message_receive_receiver) =
            mpsc::channel(DISCOVERED_DEVICES_CHANNEL_CAPACITY);
        let cloned_sender = message_received_sender.clone();

        let (connection_sender, connection_receiver) = oneshot::channel();
        let event_loop_task = tokio::spawn(async move {
            let mut cs = Some(connection_sender);
            loop {
                match mqtt_eventloop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(notification))) => {
                        let topic = String::from_utf8(notification.topic.to_vec()).unwrap();
                        info!("Received message on topic: {}", topic);
                        message_received_sender
                            .send(Action::Add(topic))
                            .await
                            .unwrap();
                    }
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        // We got a ConnAck, then we are correctly connected, tell to send stream
                        match cs {
                            Some(sender) => {
                                sender.send(Ok(())).unwrap();
                                cs = None;
                            }
                            None => {
                                info!("Reconnected to broker");
                            }
                        }
                    }
                    Ok(_) => continue,
                    Err(e) => {
                        if let Some(sender) = cs {
                            // Tell to return connection error
                            sender.send(Err(e)).unwrap();
                            break;
                        }
                        // We got disconnected drop and end discovery
                        message_received_sender.send(Action::Err(e)).await.unwrap();
                        break;
                    }
                };
            }
        });

        // Wait for connection to the broker before spawning background task and returning stream
        // this allows to return proper errors in case we are unable to connect
        match connection_receiver.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    format!("Unable to connect to broker: {}", e),
                ))
            }
            Err(_) => {
                return Err(tonic::Status::new(
                    tonic::Code::InvalidArgument,
                    "Unable to connect to broker",
                ))
            }
        }
        tokio::spawn(async move {
            let mut discovered_devices: HashMap<String, TimedDevice> = HashMap::new();
            let mqtt_uri_string = discovery_handler_config.mqtt_broker_uri.to_string();

            loop {
                trace!("discover - mqtt");
                let mut has_changed = false;
                match message_receive_receiver.recv().await {
                    Some(Action::Add(topic)) => match discovered_devices.get(&topic) {
                        Some(dev) => {
                            dev.refresh().await.unwrap();
                        }
                        None => {
                            has_changed = true;
                            info!("Adding device with topic: {}", topic);
                            discovered_devices.insert(
                                topic.clone(),
                                TimedDevice::new(
                                    Device {
                                        id: topic.clone(),
                                        properties: discovery_properties(
                                            topic.clone(),
                                            mqtt_uri_string.clone(),
                                            &discovery_handler_config.properties_prefix,
                                        ),
                                        mounts: Vec::default(),
                                        device_specs: Vec::default(),
                                    },
                                    cloned_sender.clone(),
                                    timeout_duration,
                                ),
                            );
                        }
                    },
                    Some(Action::Delete(topic)) => {
                        has_changed = true;
                        discovered_devices.remove(&topic);
                    }
                    Some(Action::Err(e)) => {
                        // We got disconnected from broker log error and quit
                        error!("{}", e);
                        break;
                    }
                    None => {
                        error!("Should not happen");
                        break;
                    }
                };

                // Before each iteration, check if receiver has dropped
                if discovered_devices_sender.is_closed() {
                    error!("discover - channel closed ... attempting to re-register with Agent");
                    register_sender.send(()).await.unwrap();
                    for (_, device) in discovered_devices {
                        device.abort()
                    }
                    event_loop_task.abort();
                    break;
                }

                if has_changed {
                    if let Err(e) = discovered_devices_sender
                        .send(Ok(DiscoverResponse {
                            devices: discovered_devices
                                .values()
                                .map(|device| device.device.clone())
                                .collect(),
                        }))
                        .await
                    {
                        error!("Failed to send discovery response with error {}", e);
                        register_sender.send(()).await.unwrap();
                        break;
                    }
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            discovered_devices_receiver,
        )))
    }
}

fn discovery_properties(
    topic: String,
    uri: String,
    properties_prefix: &Option<String>,
) -> HashMap<String, String> {
    let prefix = properties_prefix
        .as_ref()
        .map(|p| {
            if p.ends_with('_') {
                p.to_owned()
            } else {
                format!("{}_", p)
            }
        })
        .unwrap_or_default()
        .to_ascii_uppercase();
    HashMap::from([
        (format!("{prefix}MQTT_TOPIC"), topic),
        (format!("{prefix}MQTT_BROKER_URI"), uri),
    ])
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use akri_discovery_utils::discovery::v0::ByteData;
    use tonic::Status;

    use super::get_certificate_and_key;

    #[test]
    fn test_get_certificate_and_key() -> Result<(), Status> {
        let key = ByteData {
            vec: Some(
                r"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVIk2K6ho1jJb6
UKuf0HaaVBTUVttD3YbZ9MkmvejNphOSLZVhjxQqJ5wJ1d6/bjcRiJuvh6ZwJ1lo
VzShP1erRKFcM/shp8O0Q+xmIttF5i3BQF6pvWVLa/Q8ss/eDWVLO62IMkK/owLp
RP/U1qcBc5HqHqJ48+QTPs54rLAmz4k1j02jtFPv3JY5uGz4i9q6CwDjhbUL15uT
EUiiNgazKc58T3CIv8bxbYdY1tYFRXtoMmi2fQAtmvZof+KVWMkKozPTRszPGeGu
xRlW8B4WVYASMWJ9h4mCktsk05lCp+SVsphJ3x4HNQTl4qYmku7qnlis83BihBYr
tN0NoteBAgMBAAECggEATNxL/nah8QG8SJTi74Ur4EfGIzUXaYfv45XlHHWMCO2F
TUfnAQGqEfGq0dkwtPQ4I7iR/GD84qEuGvSn5CaFpRvg3PFZ9S8c4ltEWyjiznhN
s81U1f2ZE/PgZitNzxQhnVnuIJmPfLB6kkjxwX2PSHS3ACkACoJZk58oslgERloU
5Q1OjLAdWfzcwjDHnwTUw/BJGNYkuo6xkftmXCPBtbqW2jKQ8UyNMaB0Tjy7gy1Q
Y6p5xm2rP4LEECZSk2LJg0ONl2DZrMX6C2M91+DJ9GhaLwvngZU0G6zTY14rVbuE
q/WmbyS8rBDC+bL4Teqkw+6eOCoV5dqmDB9jo4pV6QKBgQDwKoluvrHpmfv1HnnJ
gsFha3mbR8kDR2OhjKRDX3skEtDwdr5dPZvwoIid79/nj3UKdEbb66gS2nH9c3Pd
BZPl2Zw6oA1NzA8fFf2UBA2cG9+SX2F5QUnx6YIH1XxqDV/Rk/aqz7JvoBbeN0n9
Pj2mE4zmttU1JCd3Fiq3wjBVMwKBgQDjL4Yq3oZYzvQeWsSFskVlY75hlqH3Umvq
l92PTokVAALE+FCXgjFksBwnqfzeu7xXjWXpohadapQPkG/A6Zf9k81cQhTDxsyO
Bp9BnNDwtdOjqJBzvKfE88L0Xdwrl2Mgub37PyvszqeeIXU3yq/aZG41HwmbXbmU
2bt0cZ54ewKBgA/QDSpwfdBOpis2bXhaFpdudxxFNrPzkFjDpNEWyUnPv1gFyXTk
KI9IUpZrg8eAR4l/rGawdml/Xn/8iQVlZ557nHCztwyHQfue/Aox1h+QKkE97HIK
XW8DG9+eK8njxYpL/rKyaCI3XSoWY9W7sl1r7hwGr7UHA14w5HEi5QHHAoGBALq7
NjEIRC68tAQ7IOqvM8D5ceMud6QcV90zxAVlTOE46A3T+BIADe8vnYSwgMrmThE8
hHa7JpFup5H/awuKNMZVdOcO3ZhpT3qxULcSWN5w5SrQgyLN/quwnB5VA4HE5dJh
ORlIvCbhWP5ti7Y238HG6Jq7Dx9nswD40c4NEW7/AoGBAOICtg5d+Pp6jLPhJmtq
RWNVeeNbV0NtO7QrSxWYt2SVefzpog+O7fP9SIUnNwKneAJ84MjOajYYwTfmCpgX
mBRgRrJOPusSm3J7E8JX51CpHYAzUAZgjdRhnwZC1a5nio7PqZ/13mS5L9Rc2ppa
4nf7zLSG2gHTGUhpU4ngu/4s
-----END PRIVATE KEY-----"
                    .as_bytes()
                    .into(),
            ),
        };
        let certs = ByteData {
            vec: Some(
                r"-----BEGIN CERTIFICATE-----
MIIDWTCCAkGgAwIBAgIIeFVlI8rqePMwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSA2YWRkMzEwHhcNMjMwODExMTIxMzUx
WhcNMjgwODEwMTIxMzUwWjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBANUiTYrqGjWMlvpQq5/QdppUFNRW20Pd
htn0ySa96M2mE5ItlWGPFConnAnV3r9uNxGIm6+HpnAnWWhXNKE/V6tEoVwz+yGn
w7RD7GYi20XmLcFAXqm9ZUtr9Dyyz94NZUs7rYgyQr+jAulE/9TWpwFzkeoeonjz
5BM+znissCbPiTWPTaO0U+/cljm4bPiL2roLAOOFtQvXm5MRSKI2BrMpznxPcIi/
xvFth1jW1gVFe2gyaLZ9AC2a9mh/4pVYyQqjM9NGzM8Z4a7FGVbwHhZVgBIxYn2H
iYKS2yTTmUKn5JWymEnfHgc1BOXipiaS7uqeWKzzcGKEFiu03Q2i14ECAwEAAaOB
mDCBlTAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFCvg8RWpQeLbs+z6QIyMetEnOCTn
MB8GA1UdIwQYMBaAFG9Im/BeNuqdgfC6wStm9GnVC6L8MBYGA1UdEQQPMA2CC2V4
YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQCFRgAbLWUndqEAN/YwoeOhiOiR
YCMcgNoFqZ/KN2qpqCvxSyjB7xHL5CjW7nr7HU+g3T7EDH/ANPVYC2QK7r79+iYE
GIyoqj/+WsddRV6X9TtdnwEWckq7UZy+keVcxWOtnjEyxH70FIZXG+soKSRuGNTL
LlQXvmzxlGfbjh6xR7GsYxN9ubEiIRqCDgJcwwlE1cLorLux19G6UpuVsSD24huw
5Juz6yRF33JpJ1dcE5fgu+95DQuTMVpJSkkCN0jbsFtZIeYdqZo4YFObzysTiSdL
POmGjPLBb+8+2lulJMLlwH5t4OPb8grXHw3ODrh+v2n9texGEejRiQ1GsjA2
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIITckr7iwQvLwwDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgM2ZiNGFjMCAXDTIzMDgxMTExNTA0M1oYDzIwNTMw
ODExMTE1MDQzWjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDZh
ZGQzMTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK1er3roaw4rnKZo
SadINVNJ5aFrZXKUt30lWAczCpy9Qyq6ku8T9uQlelzSbgSIBB3YBkY6s9HEgD+O
S20WexOUG2PFdFyiTIqeEVNgQrzCsm6yrU5k4dMX2NSoANLI5XWkX/HjKOpUBlDe
ZOySVFNjl3KIEPVCos2v0Zm0Ee+0jifNZv7DdQq2gAL7OPHw3qJQ2kIlxPxORGGQ
YxtzZqR5yQqp58bArKuuJ6I+qpAs19S+nh9zJIyEC2zEleYjazX0wuXsTpSZaAsk
ydpX73L/338y1EDibq0AaYzsYay1YSSBS4O3yWYKYlvaN0b+sfJBel5YkSSEHhjs
wHf1QfMCAwEAAaOBgzCBgDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFG9Im/Be
NuqdgfC6wStm9GnVC6L8MB8GA1UdIwQYMBaAFA6YP/kPgyxjJsQ2IY2fcQT+Z9V5
MA0GCSqGSIb3DQEBCwUAA4IBAQAXS++FlVkcfVBfGhOxNo3hjINAYzG1DMZVI0sx
5cYbpza8zOOzCya5v0LyWzr567Cf4xeHJ+jDH+VPadr7+A/2DfGNLOuvVbQpbQhd
i4C7NAEeYtoc6CFVuikiiWJypzShCWNLyyo+kfnWsTwyHLWgI2z7BZv+33PShHQy
DQfLb6ZaP5WhnAOIktXh7Wiql285efYWVAt+tilunjbwDo9cMXFRWXSsADXxHDmI
eV66nlKqNmu+RcjzMJEjwEpuV8Yx3TLvbjNAaf79OStCXb1QSnuFL3A+d793xWRs
B4Ezkc5fwpO+sXf2WKI3tktXYlITEcLPxPOxTSUUOpzY9JY9
-----END CERTIFICATE-----"
                    .as_bytes()
                    .into(),
            ),
        };

        let result = get_certificate_and_key(
            &[
                ("mqtt_broker_certificate".to_string(), certs),
                ("mqtt_broker_key".to_string(), key),
            ]
            .into(),
        )?;
        assert!(result.is_some());
        let (res_certs, _res_key) = result.unwrap();
        assert_eq!(res_certs.len(), 2);
        Ok(())
    }

    #[test]
    fn test_get_certificate_and_key_empty() -> Result<(), Status> {
        assert!(get_certificate_and_key(&HashMap::default())?.is_none());
        Ok(())
    }

    #[test]
    fn test_discovery_details_deserialization_without_properties_prefix() {
        use super::{deserialize_discovery_details, MqttDiscoveryDetails};
        let discovery_details = r#"{
            "mqttBrokerUri": "tcp://localhost:1883",
            "topics": ["topic1", "topic2"],
            "timeoutSeconds": 10
        }"#;
        let discovery_handler_config: MqttDiscoveryDetails =
            deserialize_discovery_details(discovery_details).unwrap();
        assert_eq!(discovery_handler_config.properties_prefix, None);
    }

    #[test]
    fn test_discovery_properties() {
        use super::discovery_properties;
        let topic = "topic".to_string();
        let uri = "tcp://localhost:1883".to_string();
        let properties =
            discovery_properties(topic.clone(), uri.clone(), &Some("prefix".to_string()));
        assert_eq!(properties.len(), 2);
        assert_eq!(properties.get("PREFIX_MQTT_TOPIC").unwrap(), &topic);
        assert_eq!(properties.get("PREFIX_MQTT_BROKER_URI").unwrap(), &uri);
        let properties =
            discovery_properties(topic.clone(), uri.clone(), &Some("prefix_".to_string()));
        assert_eq!(properties.len(), 2);
        assert_eq!(properties.get("PREFIX_MQTT_TOPIC").unwrap(), &topic);
        assert_eq!(properties.get("PREFIX_MQTT_BROKER_URI").unwrap(), &uri);
        let properties = discovery_properties(topic.clone(), uri.clone(), &None);
        assert_eq!(properties.len(), 2);
        assert_eq!(properties.get("MQTT_TOPIC").unwrap(), &topic);
        assert_eq!(properties.get("MQTT_BROKER_URI").unwrap(), &uri);
    }
}
