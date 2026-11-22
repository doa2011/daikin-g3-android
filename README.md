# Daikin G3 Android BLE provisioning and local migration assistant

Android application for the factory SENSOR3 G3 migration workflow.

## Current development branch

`feature/android-all-in-one-migration`

The branch is being extended from BLE-only provisioning to an Android-hosted migration stack:

- BLE provisioning: existing FF01/FF02 implementation retained.
- HTTPS compatibility server: Android foreground service on TCP 8443; persistent local self-signed certificate; upstream-compatible CA download, broker CA-info, broker login, device login and no-update check endpoints.
- MQTT TLS: compact MQTT 3.1.1 broker on TCP 18883; bounded five-topic gateway responder implementation.
- OTA: deliberately disabled until real-device protocol validation, firmware identity validation and end-to-end tests are complete.

## Important network topology

Android apps cannot normally bind privileged TCP ports 443 and 8883. The current development ports are 8443 and 18883. A router-side DNS override and TCP forwarding design is required so that G3 traffic for the upstream hostnames and ports 443/8883 reaches the Android phone. The phone should have a stable DHCP lease.

Do not trigger OTA while the five gateway replies, TLS trust, and actual device identity have not been verified. Use the Wi-Fi STA MAC from the router's DHCP lease; do not assume it equals the BLE MAC.

## Build

GitHub Actions builds a debug APK. The artifact is named `g3-provision-debug-apk`.

## Upstream protocol reference

The compatibility implementation is based on the upstream migration tools:
https://github.com/phicomm-io/iotcloud-community-firmware/tree/main/tools/daikin_g3_migrate

This project is experimental. A successful APK build does not mean Android networking, router forwarding, TLS acceptance by the G3, or OTA has been validated on hardware.
