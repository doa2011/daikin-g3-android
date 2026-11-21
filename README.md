# Daikin G3 Android BLE provisioning

Experimental Android app for factory SENSOR3 G3. Scans BLE devices, subscribes FF02, sends Wi-Fi and virtual gateway configuration via FF01. No OTA flashing.

Use 2.4GHz Wi-Fi and the Windows host LAN IPv4. Firmware and Wi-Fi connection remain unverified until hardware testing. Download APK from GitHub Actions artifact g3-provision-debug-apk.

Upstream protocol GPL-3.0: https://github.com/phicomm-io/iotcloud-community-firmware/tree/main/tools/daikin_g3_migrate