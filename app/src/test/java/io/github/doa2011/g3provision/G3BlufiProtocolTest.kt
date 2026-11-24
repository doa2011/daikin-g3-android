package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test

class G3BlufiProtocolTest {
    @Test fun wifiBodyMatchesUpstreamFieldOrder() {
        val actual = G3BlufiProtocol.buildWifiConfig("ab", "pw", "192.168.99.1", "02:00:00:00:00:01")
        val expected = byteArrayOf(
            0x42, 0x01, 0x00, 0x00, 0x02, 0x61, 0x62,
            0x02, 0x70, 0x77, 0x0c,
            0x31, 0x39, 0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x39, 0x39, 0x2e, 0x31,
            0x06, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03
        )
        assertArrayEquals(expected, actual)
    }

    @Test fun fragmentationUsesRemainingLengthAndFinalControl() {
        val body = ByteArray(45) { it.toByte() }
        val chunks = G3BlufiProtocol.fragment(body)
        assertEquals(4, chunks.size)
        assertEquals(0x10, chunks[0].control)
        assertEquals(0x10, chunks[1].control)
        assertEquals(0x10, chunks[2].control)
        assertEquals(0x00, chunks[3].control)
        assertArrayEquals(byteArrayOf(45, 0), chunks[0].payload.copyOfRange(0, 2))
        assertArrayEquals(byteArrayOf(31, 0), chunks[1].payload.copyOfRange(0, 2))
        assertArrayEquals(byteArrayOf(17, 0), chunks[2].payload.copyOfRange(0, 2))
        assertArrayEquals(body.copyOfRange(42, 45), chunks[3].payload)
        val reconstructed = chunks.flatMapIndexed { index, chunk ->
            if (index == chunks.lastIndex) chunk.payload.toList()
            else chunk.payload.copyOfRange(2, chunk.payload.size).toList()
        }.toByteArray()
        assertArrayEquals(body, reconstructed)
    }

    @Test fun versionNotificationRequiresUpstreamMinimumLength() {
        assertNull(G3BlufiProtocol.parseVersionNotification(byteArrayOf(0x41, 0, 0, 0, 1)))
        assertEquals(G3BlufiProtocol.Version(2, 7),
            G3BlufiProtocol.parseVersionNotification(byteArrayOf(0x41, 0, 0, 0, 2, 7)))
        assertNull(G3BlufiProtocol.parseVersionNotification(byteArrayOf(0x40, 0, 0, 0, 2, 7)))
    }

    @Test fun frameHeaderMatchesUpstream() {
        assertArrayEquals(
            byteArrayOf(0x4d, 0x10, 0x7f, 0x02, 0x01, 0x02),
            G3BlufiProtocol.frame(0x4d, 0x10, 0x7f, byteArrayOf(0x01, 0x02))
        )
    }

    @Test fun acceptsNonzeroLocallyAdministeredUnicastMac() {
        val body = G3BlufiProtocol.buildWifiConfig("ab", "pw", "192.168.99.1", "02:00:00:00:00:00")
        assertArrayEquals(byteArrayOf(6, 2, 0, 0, 0, 0, 0, 3), body.takeLast(8).toByteArray())
    }

    @Test fun rejectsInvalidGatewayMacAndIp() {
        try {
            G3BlufiProtocol.buildWifiConfig("ab", "pw", "192.168.99.1", "00:00:00:00:00:00")
            fail("zero gateway MAC should be rejected")
        } catch (_: IllegalArgumentException) {}
        for (invalid in listOf("01:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", "02000000000", "GG0000000001")) {
            try {
                G3BlufiProtocol.buildWifiConfig("ab", "pw", "192.168.99.1", invalid)
                fail("invalid gateway MAC should be rejected: $invalid")
            } catch (_: IllegalArgumentException) {}
        }
        try {
            G3BlufiProtocol.buildWifiConfig("ab", "pw", "192.168.999.1", "02:00:00:00:00:01")
            fail("invalid IPv4 should be rejected")
        } catch (_: IllegalArgumentException) {}
    }
}
