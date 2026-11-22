# Daikin G3 Android BLE provisioning and local migration assistant

Android application for the factory SENSOR3 G3 migration workflow.

## Development branch

`feature/android-all-in-one-migration`

- BLE provisioning: existing FF01/FF02 implementation retained.
- HTTPS compatibility server: Android foreground service, TCP 8443; persistent local self-signed certificate; upstream-compatible CA download, broker CA-info, broker login, device login and no-update check endpoints.
- MQTT TLS: compact MQTT 3.1.1 broker on TCP 8883; bounded five-topic gateway responder implementation.
- OTA: intentionally disabled until real-device validation, matching firmware selection and complete end-to-end checks.

## Network topology

Use two separate addresses:

1. **Virtual service IP**: normally the OpenWrt router LAN IP. This is the address entered into BLE provisioning and used as the HTTPS origin. DNS overrides for the three upstream Daikin hostnames should resolve to this IP.
2. **Android phone IP**: the phone's stable Wi-Fi DHCP address. The phone listens on TCP 8443 (HTTPS) and 8883 (MQTT TLS).

Configure OpenWrt DNAT/port forwarding, restricted to the G3 device where possible:

- virtual service IP TCP 443 -> Android phone IP TCP 8443
- virtual service IP TCP 8883 -> Android phone IP TCP 8883

The Android app cannot normally bind privileged TCP 443, but TCP 8443 and 8883 are unprivileged. Keep the phone on the same LAN, reserve its DHCP lease, and prevent battery optimization from stopping the foreground service.

Use the G3 Wi-Fi STA MAC from the router's DHCP lease; do not assume it equals the BLE MAC. The virtual gateway MAC remains a separate setting.

## Build

GitHub Actions builds a debug APK. Artifact name: `g3-provision-debug-apk`.

## Upstream protocol reference

https://github.com/phicomm-io/iotcloud-community-firmware/tree/main/tools/daikin_g3_migrate

This project is experimental. A successful APK build does not prove router forwarding, TLS acceptance by the G3, five gateway acknowledgements, or OTA. Do not trigger firmware update until the app explicitly reports all required preconditions as verified.
