package io.github.doa2011.g3provision

import com.jcraft.jsch.HostKey
import com.jcraft.jsch.HostKeyRepository
import com.jcraft.jsch.JSch
import com.jcraft.jsch.UserInfo
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import java.net.InetSocketAddress
import java.net.Socket

/** Two-phase OpenWrt setup: stage inert rules before Wi-Fi provisioning, bind after DHCP. */
object RouterBootstrap {
    data class Result(val output: String, val sessionId: String = "", val hostFingerprint: String = "")

    private class AcceptHostKey : HostKeyRepository {
        var fingerprint: String = ""
        override fun check(host: String, key: ByteArray): Int {
            fingerprint = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(key))
            return HostKeyRepository.OK
        }
        override fun getHostKey(): Array<HostKey> = emptyArray()
        override fun getHostKey(host: String?, type: String?): Array<HostKey> = emptyArray()
        override fun add(hostkey: HostKey, ui: UserInfo?) {}
        override fun remove(host: String?, type: String?) {}
        override fun remove(host: String?, type: String?, key: ByteArray?) {}
        override fun getKnownHostsRepositoryID(): String = "G3 automatic SSH host key acceptance"
    }

    fun prepare(routerIp: String, user: String, password: String, phoneIp: String): Result {
        require(validIp(routerIp) && validIp(phoneIp)) { "路由器或手机 IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val id = UUID.randomUUID().toString().replace("-", "")
        val specs = listOf(
            listOf("dns_udp", "udp", "53", "1053"),
            listOf("dns_tcp", "tcp", "53", "1053"),
            listOf("https", "tcp", "443", "8443"),
            listOf("mqtt", "tcp", "8883", "18883")
        )
        val commands = specs.flatMap { spec ->
            val section = "g3mig_${id}_${spec[0]}"
            listOf(
                "uci set firewall.$section=redirect",
                "uci set firewall.$section.name='G3 migration ${spec[0]}'",
                "uci set firewall.$section.g3mig_owner='$id'",
                "uci set firewall.$section.src=lan",
                if (spec[0] == "https" || spec[0] == "mqtt") "uci set firewall.$section.src_dip='$routerIp'" else "",
                "uci set firewall.$section.src_dport=${spec[2]}",
                "uci set firewall.$section.dest=lan",
                "uci set firewall.$section.dest_ip='$phoneIp'",
                "uci set firewall.$section.dest_port=${spec[3]}",
                "uci set firewall.$section.proto=${spec[1]}",
                "uci set firewall.$section.target=DNAT",
                "uci set firewall.$section.enabled=0"
            ).filter { it.isNotEmpty() }
        }
        val names = specs.joinToString(" ") { "g3mig_${id}_${it[0]}" }
        val script = (listOf(
            "set -eu",
            "[ -z \"${'$'}(uci changes firewall)\" ] || { echo 'Firewall has pending UCI changes' >&2; exit 62; }",
            "for section in $names; do if uci -q get \"firewall.${'$'}section\" >/dev/null 2>&1; then echo \"Session already exists: ${'$'}section\" >&2; exit 63; fi; done",
            "umask 077",
            "cp /etc/config/firewall /root/g3-migration-$id.firewall.bak"
        ) + commands + listOf(
            "uci commit firewall",
            "/etc/init.d/firewall reload",
            "echo 'Prepared disabled G3 migration session $id'"
        )).joinToString("\n") + "\n"
        val executed = run(routerIp,user,password,script)
        return Result(executed.first,id,executed.second)
    }

    fun bind(routerIp: String, user: String, password: String, sessionId: String, g3Ip: String): Result {
        require(validIp(routerIp) && validIp(g3Ip) && sessionId.matches(Regex("[a-f0-9]{32}")))
        val commands = listOf("dns_udp", "dns_tcp", "https", "mqtt").flatMap { suffix ->
            val section = "g3mig_${sessionId}_$suffix"
            listOf(
                "owner=\"${'$'}(uci -q get firewall.$section.g3mig_owner || true)\"",
                "[ \"${'$'}owner\" = '$sessionId' ] || { echo 'Missing/foreign rule: $section' >&2; exit 61; }",
                "uci set firewall.$section.src_ip='$g3Ip'",
                "uci set firewall.$section.enabled=1"
            )
        }
        val script = (listOf("set -eu", "[ -z \"${'$'}(uci changes firewall)\" ] || exit 64") + commands +
            listOf("uci commit firewall", "/etc/init.d/firewall reload", "echo 'G3 DHCP identity bound: $g3Ip'")).joinToString("\n") + "\n"
        val executed = run(routerIp,user,password,script)
        return Result(executed.first,sessionId,executed.second)
    }

    fun readDhcpLeases(routerIp: String, user: String, password: String): Result {
        val executed = run(routerIp,user,password,"set -eu; cat /tmp/dhcp.leases\n")
        return Result(executed.first,hostFingerprint=executed.second)
    }

    fun cleanup(routerIp: String, user: String, password: String, sessionId: String): Result {
        require(validIp(routerIp) && sessionId.matches(Regex("[a-f0-9]{32}")))
        val commands = listOf("dns_udp", "dns_tcp", "https", "mqtt").flatMap { suffix ->
            val section = "g3mig_${sessionId}_$suffix"
            listOf(
                "owner=\"${'$'}(uci -q get firewall.$section.g3mig_owner || true)\"",
                "if [ -n \"${'$'}owner\" ] && [ \"${'$'}owner\" != '$sessionId' ]; then echo 'Foreign rule: $section' >&2; exit 65; fi",
                "[ -z \"${'$'}owner\" ] || uci -q delete firewall.$section"
            )
        }
        val script = (listOf("set -eu", "[ -z \"${'$'}(uci changes firewall)\" ] || exit 66") + commands +
            listOf("uci commit firewall", "/etc/init.d/firewall reload", "rm -f /root/g3-migration-$sessionId.firewall.bak", "echo 'Session $sessionId removed'")).joinToString("\n") + "\n"
        val executed = run(routerIp,user,password,script)
        return Result(executed.first,sessionId,executed.second)
    }

    private fun run(host: String, user: String, password: String, script: String): Pair<String,String> {
        // Distinguish LAN reachability/Dropbear port failures from SSH authentication and exec-channel failures.
        try {
            Socket().use { probe ->
                probe.connect(InetSocketAddress(host, 22), 4000)
            }
        } catch (e: Exception) {
            throw IllegalStateException("TCP 22 不可达：请确认手机与 OpenWrt 在同一 LAN、路由器 IP 正确且 Dropbear 正在监听。原始错误：${e.message}", e)
        }

        val keys = AcceptHostKey()
        val session = JSch().getSession(user,host,22)
        session.setPassword(password)
        session.hostKeyRepository = keys
        session.setConfig("StrictHostKeyChecking","yes")
        session.setConfig("PreferredAuthentications","password,keyboard-interactive")
        try {
            try {
                session.connect(15000)
            } catch (e: Exception) {
                throw IllegalStateException("TCP 22 可达，但 SSH 握手/认证失败：请检查账号、密码、Dropbear 认证配置。原始错误：${e.message}", e)
            }
            val channel = try {
                session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            } catch (e: Exception) {
                throw IllegalStateException("SSH 已连接，但无法创建 exec 命令通道：${e.message}", e)
            }
            channel.setCommand("sh -s")
            val stdout = ByteArrayOutputStream()
            val stderr = ByteArrayOutputStream()
            channel.setOutputStream(stdout)
            channel.setErrStream(stderr)
            try {
                channel.connect(12000)
            } catch (e: Exception) {
                throw IllegalStateException("SSH 已认证，但 exec 通道建立超时：${e.message}", e)
            }
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline = System.currentTimeMillis() + 25000
            while (!channel.isClosed && System.currentTimeMillis() < deadline) Thread.sleep(100)
            if (!channel.isClosed) { channel.disconnect(); error("OpenWrt SSH 命令执行超过 25 秒") }
            val output = stdout.toString("UTF-8") + stderr.toString("UTF-8")
            val code = channel.exitStatus
            channel.disconnect()
            check(code == 0) { "OpenWrt 命令失败（退出码 $code）：$output" }
            return output to keys.fingerprint
        } finally { session.disconnect() }
    }

    private fun validIp(ip: String): Boolean = ip.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
        ip.split(".").all { it.toInt() in 0..255 }
}