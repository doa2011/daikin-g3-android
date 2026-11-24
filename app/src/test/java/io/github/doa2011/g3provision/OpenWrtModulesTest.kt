package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

class OpenWrtModulesTest {
    private fun question(name: String, type: Int): ByteArray {
        val bytes = ByteArrayOutputStream()
        DataOutputStream(bytes).use { out ->
            out.writeShort(0x1234); out.writeShort(0x0100)
            out.writeShort(1); out.writeShort(0); out.writeShort(0); out.writeShort(0)
            for (label in name.split('.')) {
                val part = label.toByteArray(Charsets.US_ASCII)
                out.writeByte(part.size); out.write(part)
            }
            out.writeByte(0); out.writeShort(type); out.writeShort(1)
        }
        return bytes.toByteArray()
    }

    @Test fun factoryHostsResolveToRouterForBothTransports() {
        val dns = DnsRedirectServer("192.168.99.1", "192.168.99.1")
        for (name in listOf("newlifemulti.daikin-china.com.cn", "newlifemulti-cdh.daikin-china.com.cn", "newlifemulti-cdh-core.daikin-china.com.cn")) {
            for (tcp in listOf(false, true)) {
                val a = dns.answerOrForward(question(name, 1), tcp)
                assertEquals(1, a[7].toInt())
                assertArrayEquals(byteArrayOf(192.toByte(),168.toByte(),99,1), a.takeLast(4).toByteArray())
                val q = question(name, 28)
                val aaaa = dns.answerOrForward(q, tcp)
                assertEquals(0, aaaa[7].toInt())
                assertEquals(q.size, aaaa.size)
            }
        }
    }

    @Test fun malformedQuestionRejected() {
        try { DnsRedirectServer("192.168.99.1", "192.168.99.1").answerOrForward(ByteArray(12), false); fail("malformed query accepted") }
        catch (_: IllegalArgumentException) {}
    }

    @Test fun generatedRulesScopeEveryRedirectToG3AndUseExpectedPorts() {
        val script = RouterMigration.applyScript("192.168.99.1", "192.168.99.2", "192.168.99.3")
        for ((id, port) in listOf("dns_udp" to 1053, "dns_tcp" to 1053, "https" to 8443, "mqtt" to 18883)) {
            assertTrue(script.contains("firewall.g3mig_$id.src_ip='192.168.99.3'"))
            assertTrue(script.contains("firewall.g3mig_$id.dest_ip='192.168.99.2'"))
            assertTrue(script.contains("firewall.g3mig_$id.dest_port=$port"))
        }
        assertFalse(script.contains("uci set dhcp."))
    }

    @Test fun cleanupRemovesOnlyFourKnownSectionsAndEndsWithNewline() {
        val script = RouterMigration.removeScript()
        val deletes = script.lines().filter { it.startsWith("uci -q delete") }
        assertEquals(listOf("dns_udp","dns_tcp","https","mqtt").map { "uci -q delete firewall.g3mig_$it || true" }, deletes)
        assertTrue(script.endsWith("\n"))
        assertFalse(script.contains("cp "))
    }
}
