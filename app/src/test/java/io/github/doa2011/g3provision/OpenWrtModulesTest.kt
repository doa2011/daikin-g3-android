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

    @Test fun applyRejectsExistingSectionsBeforeAnyMutation() {
        val script = RouterMigration.applyScript("192.168.99.1", "192.168.99.2", "192.168.99.3")
        val firstWrite = script.indexOf("uci set ")
        assertTrue(firstWrite > 0)
        assertTrue(script.indexOf("exit 21") in 0 until firstWrite)
        assertTrue(script.indexOf("exit 22") in 0 until firstWrite)
        assertFalse(script.contains("uci -q delete "))
        assertTrue(script.contains("uci changes firewall"))
    }

    @Test fun factoryAndPhonePortsMatchRedirectContract() {
        assertEquals(53, MigrationPorts.FACTORY_DNS)
        assertEquals(443, MigrationPorts.FACTORY_HTTPS)
        assertEquals(8883, MigrationPorts.FACTORY_MQTT_TLS)
        assertEquals(1053, MigrationPorts.DNS)
        assertEquals(8443, MigrationPorts.HTTPS)
        assertEquals(18883, MigrationPorts.MQTT_TLS)
        val script = RouterMigration.applyScript("192.168.99.1", "192.168.99.2", "192.168.99.3")
        assertTrue(script.contains("g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}"))
        assertTrue(script.contains("g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}"))
    }

    @Test fun cleanupRemovesOnlyFourKnownSectionsAndEndsWithNewline() {
        val script = RouterMigration.removeScript()
        val deletes = script.lines().filter { it.startsWith("uci -q delete") }
        assertEquals(listOf("dns_udp","dns_tcp","https","mqtt").map { "uci -q delete firewall.g3mig_$it || true" }, deletes)
        assertTrue(script.endsWith("\n"))
        // Match a shell command, not the suffix of the section name dns_tcp.
        val copyCommand = Regex("""(?:^|[;|&]\s*)\s*(?:/bin/)?cp(?:\s|$)""")
        assertFalse(script.lines().any { copyCommand.containsMatchIn(it) })
        assertTrue(copyCommand.containsMatchIn("cp /tmp/backup /etc/config/firewall"))
        assertTrue(copyCommand.containsMatchIn("test -f /tmp/backup && cp /tmp/backup /etc/config/firewall"))
        assertFalse(copyCommand.containsMatchIn("uci -q delete firewall.g3mig_dns_tcp || true"))
    }
}
