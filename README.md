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


## Bundled G3 firmware / 内置 G3 固件

The Android CI build downloads the exact upstream RC7 G3 ESP32 OTA raw application and verifies its SHA-256, byte length, ESP32 image header, G3 model marker and full-application variant before Gradle packages it into the APK assets.

- Upstream release: `v1.0.0-rc.7` (release candidate)
- Asset: `daikin_BRY88BBA15G.ota.bin.raw`
- Device: `BRY88BBA15G / SENSOR3_ESP32`
- Size: `1,288,544` bytes
- SHA-256: `b588e0d33bffe93be509441d39a949f4427a930245bd8b43b13dbb27cca9ecff`
- Factory OTA compatibility label: `V99.00.00` (temporary trigger label; not the installed community firmware version)

The app automatically copies the bundled image to its private files directory and verifies SHA-256 plus the upstream image markers before offering it. Manual firmware selection remains an advanced override. The ESP32 image is bundled; the optional G3 screen MCU application/resource files are not part of this first-stage ESP32 migration APK because the upstream migration guide installs the screen update separately after ESP32 migration.

For local builds, run `bash scripts/prepare_g3_firmware.sh` before `gradle :app:assembleDebug`. GitHub Actions performs this automatically.
