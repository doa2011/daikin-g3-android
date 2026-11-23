# Daikin G3 Android BLE provisioning

Experimental Android app for factory SENSOR3 G3. Scans BLE devices, subscribes FF02, sends Wi-Fi and virtual gateway configuration via FF01. No OTA flashing.

Use 2.4GHz Wi-Fi and the Windows host LAN IPv4. Firmware and Wi-Fi connection remain unverified until hardware testing. Download APK from GitHub Actions artifact g3-provision-debug-apk.

Upstream protocol GPL-3.0: https://github.com/phicomm-io/iotcloud-community-firmware/tree/main/tools/daikin_g3_migrate

## S24 / OpenWrt one-click migration work in progress

Development branch: `feature/s24-rootless-oneclick-migration`.

The current implementation milestone adds:
- An Android-side split DNS listener on TCP/UDP 1053. Only the three factory migration hostnames receive the OpenWrt LAN address; other queries are forwarded to the router's DNS service. AAAA responses for those three names are suppressed so the stock client cannot bypass the IPv4 migration endpoint.
- An SSH client with explicit SHA-256 host-key pinning. The router password is held only in the Activity field and cleared after each attempt; it is not written to disk.
- Four named OpenWrt firewall redirects scoped to the configured G3 source IPv4: UDP/TCP DNS to the phone's 1053 listener, and router-LAN TCP 443/8883 to phone TCP 8443/18883. No global dnsmasq address overrides or DHCP DNS changes are made.
- A cleanup action that removes only the four named migration redirects and leaves unrelated firewall configuration intact.

**Important: this is not yet a complete migrator.** The Android HTTPS factory-compatibility server, TLS MQTT broker and gateway acknowledgement state machine, firmware hosting/validation, ESP32 OTA orchestration, and automatic screen-MCU OTA are not implemented in this milestone. Do not apply the router rules to a live G3 yet; without the HTTPS/MQTT listeners, the migration endpoints are not ready. Keep the app open while the current DNS listener is running.

Router rule setup requires the G3's current Wi-Fi STA IPv4, the S24's current LAN IPv4, the OpenWrt LAN IPv4, and the verified OpenWrt SSH host-key fingerprint. The first SSH attempt intentionally fails closed and reports the fingerprint; verify it through a trusted channel before entering it and retrying. The router changes are limited to the selected G3 source IP.
