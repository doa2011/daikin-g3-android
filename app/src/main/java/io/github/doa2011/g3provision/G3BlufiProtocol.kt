package io.github.doa2011.g3provision

import java.nio.charset.StandardCharsets

/** Wire-compatible BLUFi framing for the stock G3 custom Wi-Fi/gateway message. */
internal object G3BlufiProtocol {
    data class Chunk(val payload: ByteArray, val control: Int)
    data class Version(val major: Int, val minor: Int)

    fun parseVersionNotification(data: ByteArray): Version? {
        if (data.size < 6 || (data[0].toInt() and 0xff) != 0x41) return null
        return Version(data[4].toInt() and 0xff, data[5].toInt() and 0xff)
    }

    fun buildWifiConfig(ssid: String, password: String, gatewayIp: String, gatewayMac: String): ByteArray {
        val ssidBytes = ssid.toByteArray(StandardCharsets.UTF_8)
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        require(ssidBytes.size in 1..32) { "SSID 必须为 1..32 字节 UTF-8" }
        require(passwordBytes.size <= 64) { "Wi-Fi 密码不能超过 64 字节 UTF-8" }

        val octets = gatewayIp.split('.')
        require(octets.size == 4 && octets.all { it.isNotEmpty() && it.all(Char::isDigit) && (it.toIntOrNull()?.let { n -> n in 0..255 } == true) }) {
            "网关 IPv4 地址无效"
        }
        val canonicalIp = octets.joinToString(".") { it.toInt().toString() }
        val ipBytes = canonicalIp.toByteArray(StandardCharsets.US_ASCII)
        require(ipBytes.size in 7..15) { "网关 IPv4 地址长度无效" }

        val mac = parseGatewayMac(gatewayMac)

        // Keep this byte layout identical to upstream provision_linux.py:
        // 42 01 00 00 | ssid-len | ssid | password-len | password |
        // gateway-ip-len | gateway-ip | 06 | gateway-mac | 03
        return byteArrayOf(0x42, 0x01, 0x00, 0x00, ssidBytes.size.toByte()) +
            ssidBytes + byteArrayOf(passwordBytes.size.toByte()) + passwordBytes +
            byteArrayOf(ipBytes.size.toByte()) + ipBytes + byteArrayOf(0x06) + mac + byteArrayOf(0x03)
    }

    private fun parseGatewayMac(gatewayMac: String): ByteArray {
        val compactMac = gatewayMac.replace(":", "").replace("-", "").uppercase()
        require(compactMac.matches(Regex("[0-9A-F]{12}"))) { "虚拟网关 MAC 必须为 12 位十六进制" }
        val mac = compactMac.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        require((mac[0].toInt() and 1) == 0 && mac.any { it.toInt() != 0 }) {
            "虚拟网关 MAC 必须为非零单播地址"
        }
        return mac
    }

    fun buildGatewayConfig(gatewayMac: String): ByteArray =
        byteArrayOf(0x42, 0x03, 0x00, 0x00, 0x06) + parseGatewayMac(gatewayMac) + byteArrayOf(0x03)

    /**
     * Upstream BLUFi fragmentation: while remaining body > 16 bytes, send
     * [remaining-length little-endian, first 14 body bytes] with control 0x10;
     * the final <=16 bytes use control 0x00.
     */
    fun fragment(body: ByteArray): List<Chunk> {
        require(body.isNotEmpty()) { "BLUFi 配网数据不能为空" }
        val result = ArrayList<Chunk>()
        var offset = 0
        while (body.size - offset > 16) {
            val remaining = body.size - offset
            val payload = byteArrayOf((remaining and 0xff).toByte(), ((remaining ushr 8) and 0xff).toByte()) +
                body.copyOfRange(offset, offset + 14)
            result.add(Chunk(payload, 0x10))
            offset += 14
        }
        result.add(Chunk(body.copyOfRange(offset, body.size), 0x00))
        return result
    }

    fun frame(type: Int, control: Int, sequence: Int, payload: ByteArray): ByteArray {
        require(type in 0..255 && control in 0..255 && sequence in 0..255)
        require(payload.size <= 255) { "BLUFi 单帧 payload 超过 255 字节" }
        return byteArrayOf(type.toByte(), control.toByte(), sequence.toByte(), payload.size.toByte()) + payload
    }
}
