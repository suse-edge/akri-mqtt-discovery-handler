# Akri MQTT Discovery Handler

A simple Discovery Handler for MQTT based devices, aims to be a reference implementation for [MQTT akri proposal](https://github.com/project-akri/akri-docs/pull/80).

## Deploy

```sh
  helm upgrade akri akri-helm-charts/akri \
  $AKRI_HELM_CRICTL_CONFIGURATION \
  --set custom.discovery.enabled=true  \
  --set custom.discovery.image.repository=ghcr.io/myusername/mqtt-discovery-handler \
  --set custom.discovery.image.tag=v1 \
  --set custom.discovery.name=akri-mqtt-discovery 
```

## Build

```sh
docker buildx build --platform linux/arm64,linux/amd64 -t ghcr.io/myuser/mqtt-discovery-handler:v1 -f Dockerfile.discovery-handler .
```

> Note: this does not seem to be executing correctly once built

## Run Locally
```sh
sudo -E RUST_LOG=info DISCOVERY_HANDLERS_DIRECTORY=/var/lib/akri AGENT_NODE_NAME=nodename $HOME/.cargo/bin/cargo run
```

## Apply Configuration

```sh
kubectl apply -f deploy/akri-mqtt-configuration.yaml
```