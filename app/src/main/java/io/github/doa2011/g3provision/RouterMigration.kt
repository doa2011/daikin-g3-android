package io.github.doa2011.g3provision

import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.JSchException
import com.jcraft.jsch.UserInfo
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

/** Per-device OpenWrt redirects. No global DNS or DHCP settings are changed. */
object RouterMigration {
    data class Result(val output: String, val fingerprint: String, val sessionId: String = "")
    private class PinRepository(private val expected: String = "") : HostKeyRepository {
        var observed = ""
        override fun check(host: String, key: ByteArray): Int {
            observed = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
            return if (expected.isBlank() || expected == observed) 0 else 1
        }
        override fun getHostKey(): Array<HostKey> = emptyArray()
        override fun getHostKey(host: String, type: String): Array<HostKey> = emptyArray()
        override fun add(hostkey: HostKey, ui: UserInfo?) {}
        override fun remove(host: String, type: String) {}
        override fun remove(host: String, type: String, key: ByteArray) {}
        override fun getKnownHostsRepositoryID(): String = "G3 pinned host key"
    }

    fun apply(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String) =
        run(host,user,password,fingerprint,routerIp,phoneIp,g3Ip,true)
    fun remove(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String) =
        run(host,user,password,fingerprint,routerIp,phoneIp,g3Ip,false)

    /** Pre-create disabled rules before G3 has joined Wi-Fi; only router credentials are required. */
    fun prepareSession(host: String, user: String, password: String, phoneIp: String): Result {
        require(validIpv4(host) && validIpv4(phoneIp) && user.isNotBlank() && password.isNotEmpty())
        val id = java.util.UUID.randomUUID().toString().replace("-", "")
        val rows = listOf(
            listOf("dns_udp", "udp", MigrationPorts.FACTORY_DNS, MigrationPorts.DNS),
            listOf("dns_tcp", "tcp", MigrationPorts.FACTORY_DNS, MigrationPorts.DNS),
            listOf("https", "tcp", MigrationPorts.FACTORY_HTTPS, MigrationPorts.HTTPS),
            listOf("mqtt", "tcp", MigrationPorts.FACTORY_MQTT_TLS, MigrationPorts.MQTT_TLS)
        )
        val commands = rows.flatMap { row ->
            val section = "g3mig_${id}_${row[0]}"
            listOf(
                "uci set firewall.$section=redirect",
                "uci set firewall.$section.name='G3 migration ${row[0]}'",
                "uci set firewall.$section.g3mig_owner='$id'",
                "uci set firewall.$section.src=lan",
                if (row[0] == "https" || row[0] == "mqtt") "uci set firewall.$section.src_dip='$host'" else "",
                "uci set firewall.$section.src_dport=${row[2]}",
                "uci set firewall.$section.dest=lan",
                "uci set firewall.$section.dest_ip='$phoneIp'",
                "uci set firewall.$section.dest_port=${row[3]}",
                "uci set firewall.$section.proto=${row[1]}",
                "uci set firewall.$section.target=DNAT",
                "uci set firewall.$section.enabled=0"
            ).filter { it.isNotEmpty() }
        }
        val names = rows.joinToString(" ") { "g3mig_${id}_${it[0]}" }
        val script = (listOf(
            "set -eu",
            "[ -z \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}(uci changes firewall)\" ] || { echo 'Firewall has pending UCI changes' >&2; exit 62; }",
            "for section in $names; do if uci -q get \"firewall.${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}section\" >/dev/null 2>&1; then echo \"Session already exists: ${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}section\" >&2; exit 63; fi; done",
            "umask 077",
            "cp /etc/config/firewall /root/g3-migration-$id.firewall.bak"
        ) + commands + listOf("uci commit firewall", "/etc/init.d/firewall reload", "echo 'Prepared disabled G3 migration session $id'")).joinToString("\n") + "\n"
        return executeSessionScript(host,user,password,"",script).copy(sessionId=id)
    }

    /** Enable this session only after the G3 DHCP lease has been identified. */
    fun bindSession(host: String, user: String, password: String, sessionId: String, g3Ip: String): Result {
        require(validIpv4(host) && validIpv4(g3Ip) && sessionId.matches(Regex("[a-f0-9]{32}")))
        val commands = listOf("dns_udp", "dns_tcp", "https", "mqtt").flatMap { suffix ->
            val section = "g3mig_${sessionId}_$suffix"
            listOf(
                "owner=\"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}(uci -q get firewall.$section.g3mig_owner || true)\"",
                "[ \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}owner\" = '$sessionId' ] || { echo 'Missing or foreign session rule: $section' >&2; exit 61; }",
                "uci set firewall.$section.src_ip='$g3Ip'",
                "uci set firewall.$section.enabled=1"
            )
        }
        val script = (listOf("set -eu", "[ -z \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}(uci changes firewall)\" ] || exit 62") + commands +
            listOf("uci commit firewall", "/etc/init.d/firewall reload", "echo 'G3 DHCP address bound to session $sessionId'")).joinToString("\n") + "\n"
        return executeSessionScript(host,user,password,"",script)
    }

    fun removePreparedSession(host: String, user: String, password: String, sessionId: String): Result {
        require(validIpv4(host) && sessionId.matches(Regex("[a-f0-9]{32}")))
        val commands = listOf("dns_udp", "dns_tcp", "https", "mqtt").flatMap { suffix ->
            val section = "g3mig_${sessionId}_$suffix"
            listOf(
                "owner=\"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}(uci -q get firewall.$section.g3mig_owner || true)\"",
                "if [ -n \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}owner\" ] && [ \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}owner\" != '$sessionId' ]; then echo 'Foreign rule: $section' >&2; exit 65; fi",
                "[ -z \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}owner\" ] || uci -q delete firewall.$section"
            )
        }
        val script = (listOf("set -eu", "[ -z \"${'
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
}(uci changes firewall)\" ] || exit 64") + commands +
            listOf("uci commit firewall", "/etc/init.d/firewall reload", "rm -f /root/g3-migration-$sessionId.firewall.bak", "echo 'Session $sessionId removed'")).joinToString("\n") + "\n"
        return executeSessionScript(host,user,password,"",script)
    }

    fun discoverDhcpLeases(host: String, user: String, password: String): Result =
        executeSessionScript(host,user,password,"","set -eu; cat /tmp/dhcp.leases\n")

    private fun validIpv4(value: String): Boolean = value.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
        value.split(".").all { it.toInt() in 0..255 }
    /** Execute the UUID-scoped transaction generated by RouterSessionPlan over pinned SSH. */
    fun applySession(host: String, user: String, password: String, fingerprint: String,
                     routerIp: String, phoneIp: String, g3Ip: String): Result {
        val plan = RouterSessionPlan.create(routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.applyScript())
    }

    /** Remove only the sections owned by the supplied session id. */
    fun removeSession(host: String, user: String, password: String, fingerprint: String,
                      routerIp: String, phoneIp: String, g3Ip: String, sessionId: String): Result {
        val plan = RouterSessionPlan(sessionId, routerIp, phoneIp, g3Ip)
        return executeSessionScript(host, user, password, fingerprint, plan.cleanupScript())
    }

    private fun executeSessionScript(host: String, user: String, password: String,
                                     fingerprint: String, script: String): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && user.isNotBlank() && password.isNotEmpty())
        require(fingerprint.isBlank() || fingerprint.startsWith("SHA256:"))
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            channel.connect(8000)
            channel.outputStream.use {
                it.write(script.toByteArray(StandardCharsets.UTF_8))
                it.flush()
            }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) {
                channel.disconnect()
                error("OpenWrt 会话事务执行超时；请先查询路由器会话状态，不要盲目重复安装")
            }
            val code = channel.exitStatus
            channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 会话事务失败（退出码 $code）：$output" }
            return Result(output, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("路由器主机密钥指纹不匹配：${pin.observed}")
            throw e
        } finally {
            session.disconnect()
        }
    }

    private fun run(host: String, user: String, password: String, fingerprint: String, routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun validIp(v: String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) && v.split(".").all { it.toInt() in 0..255 }
        require(validIp(host) && validIp(routerIp) && validIp(phoneIp) && validIp(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin = PinRepository(fingerprint.trim())
        val session = JSch().getSession(user, host, 22)
        session.setPassword(password)
        session.hostKeyRepository = pin
        session.setConfig("StrictHostKeyChecking", "yes")
        try {
            session.connect(12000)
            val channel = session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream(); val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout); channel.setErrStream(stderr); channel.connect(8000)
            val script = if (enable) applyScript(routerIp, phoneIp, g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 20000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code = channel.exitStatus; channel.disconnect()
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            check(code == 0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if (enable) "G3 专用规则已启用" else "G3 专用规则已撤销" }, pin.observed)
        } catch (e: Exception) {
            if (e is JSchException && pin.observed.isNotBlank() && fingerprint.trim() != pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    internal fun applyScript(router: String, phone: String, g3: String): String {
        require(listOf(router, phone, g3).distinct().size == 3) { "路由器、手机和 G3 地址必须不同" }
        val p = "'$phone'"; val g = "'$g3'"; val r = "'$router'"
        return """
set -eu
if uci -q get firewall.g3mig_dns_udp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_udp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_dns_tcp >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_dns_tcp" >&2
    exit 21
fi
if uci -q get firewall.g3mig_https >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_https" >&2
    exit 21
fi
if uci -q get firewall.g3mig_mqtt >/dev/null 2>&1; then
    echo "Existing migration section; refusing to overwrite: g3mig_mqtt" >&2
    exit 21
fi
if [ -n "${'$'}(uci changes firewall)" ]; then
    echo "Uncommitted firewall changes; refusing to modify." >&2
    exit 22
fi
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name="G3 migration DNS UDP"
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name="G3 migration DNS TCP"
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=${MigrationPorts.FACTORY_DNS}
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=${MigrationPorts.DNS}
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name="G3 migration HTTPS"
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=${MigrationPorts.FACTORY_HTTPS}
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=${MigrationPorts.HTTPS}
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name="G3 migration MQTT TLS"
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=${MigrationPorts.FACTORY_MQTT_TLS}
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=${MigrationPorts.MQTT_TLS}
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo "G3-only migration redirects installed."
""".trimIndent() + "\n"
    }

    internal fun removeScript(): String = """
set -eu
uci -q delete firewall.g3mig_dns_udp || true
uci -q delete firewall.g3mig_dns_tcp || true
uci -q delete firewall.g3mig_https || true
uci -q delete firewall.g3mig_mqtt || true
uci commit firewall
/etc/init.d/firewall reload
echo "Only G3 migration redirects removed; unrelated firewall settings preserved."
""".trimIndent() + "\n"
}
