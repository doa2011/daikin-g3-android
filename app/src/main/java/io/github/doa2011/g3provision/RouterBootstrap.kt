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

    /** Supplies the already-entered password to JSch's password and keyboard-interactive callbacks. */
    private class PasswordAuth(private val secret: String) : UserInfo, com.jcraft.jsch.UIKeyboardInteractive {
        override fun getPassword(): String = secret
        override fun getPassphrase(): String? = null
        override fun promptPassword(message: String): Boolean = true
        override fun promptPassphrase(message: String): Boolean = false
        override fun promptYesNo(message: String): Boolean = false
        override fun showMessage(message: String) {}
        override fun promptKeyboardInteractive(
            destination: String, name: String, instruction: String,
            prompt: Array<String>, echo: BooleanArray
        ): Array<String> = Array(prompt.size) { index ->
            if (index < echo.size && echo[index]) "" else secret
        }
    }

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
        require(validIp(routerIp) && validIp(phoneIp) && routerIp != phoneIp)
        require(user.isNotBlank() && password.isNotEmpty())
        val id = UUID.randomUUID().toString().replace("-", "")
        val https = "g3mig_\${id}_https"
        val mqtt = "g3mig_\${id}_mqtt"
        val script = """
set -eu
ID='$id'; PHONE='$phoneIp'; ROUTER='$routerIp'; HTTPS='$https'; MQTT='$mqtt'
SESSION="/root/g3-migration-$id.session"
FWBACK="/root/g3-migration-$id.firewall.bak"; DHCPBACK="/root/g3-migration-$id.dhcp.bak"
[ -z "$(uci changes firewall)" ] && [ -z "$(uci changes dhcp)" ]
uci -q get dhcp.@dnsmasq[0] >/dev/null
for s in "${'$'}HTTPS" "${'$'}MQTT"; do ! uci -q get "firewall.${'$'}s" >/dev/null 2>&1 || exit 63; done
[ ! -e "${'$'}SESSION" ] || exit 63
umask 077; cp /etc/config/firewall "${'$'}FWBACK"; cp /etc/config/dhcp "${'$'}DHCPBACK"
rollback() { rc=${'$'}?; if [ "${'$'}rc" -ne 0 ]; then cp "${'$'}FWBACK" /etc/config/firewall; cp "${'$'}DHCPBACK" /etc/config/dhcp; uci revert firewall || true; uci revert dhcp || true; /etc/init.d/dnsmasq restart || true; /etc/init.d/firewall reload || true; rm -f "${'$'}SESSION" "${'$'}FWBACK" "${'$'}DHCPBACK"; fi; }
trap rollback EXIT HUP INT TERM
uci add_list dhcp.@dnsmasq[0].server="/newlifemulti.daikin-china.com.cn/${'$'}PHONE#1053"
uci add_list dhcp.@dnsmasq[0].server="/newlifemulti-cdh.daikin-china.com.cn/${'$'}PHONE#1053"
uci add_list dhcp.@dnsmasq[0].server="/newlifemulti-cdh-core.daikin-china.com.cn/${'$'}PHONE#1053"
uci set firewall.${'$'}HTTPS=redirect; uci set firewall.${'$'}HTTPS.name='G3 migration Daikin HTTPS'
uci set firewall.${'$'}HTTPS.g3mig_owner="${'$'}ID"; uci set firewall.${'$'}HTTPS.src=lan
uci set firewall.${'$'}HTTPS.src_dip="${'$'}ROUTER"; uci set firewall.${'$'}HTTPS.src_dport=443
uci set firewall.${'$'}HTTPS.dest=lan; uci set firewall.${'$'}HTTPS.dest_ip="${'$'}PHONE"
uci set firewall.${'$'}HTTPS.dest_port=8443; uci set firewall.${'$'}HTTPS.proto=tcp
uci set firewall.${'$'}HTTPS.target=DNAT; uci set firewall.${'$'}HTTPS.enabled=1
uci set firewall.${'$'}MQTT=redirect; uci set firewall.${'$'}MQTT.name='G3 migration Daikin MQTT TLS'
uci set firewall.${'$'}MQTT.g3mig_owner="${'$'}ID"; uci set firewall.${'$'}MQTT.src=lan
uci set firewall.${'$'}MQTT.src_dip="${'$'}ROUTER"; uci set firewall.${'$'}MQTT.src_dport=8883
uci set firewall.${'$'}MQTT.dest=lan; uci set firewall.${'$'}MQTT.dest_ip="${'$'}PHONE"
uci set firewall.${'$'}MQTT.dest_port=18883; uci set firewall.${'$'}MQTT.proto=tcp
uci set firewall.${'$'}MQTT.target=DNAT; uci set firewall.${'$'}MQTT.enabled=1
uci commit dhcp; uci commit firewall
/etc/init.d/dnsmasq restart; /etc/init.d/firewall reload
for d in newlifemulti.daikin-china.com.cn newlifemulti-cdh.daikin-china.com.cn newlifemulti-cdh-core.daikin-china.com.cn; do
 e="/${'$'}d/${'$'}PHONE#1053"; uci -q get dhcp.@dnsmasq[0].server | grep -Fqx "${'$'}e"
done
if command -v fw4 >/dev/null 2>&1; then
 nft -a list ruleset > "/tmp/g3mig-${'$'}ID.nft"
 grep -Fq 'G3 migration Daikin HTTPS' "/tmp/g3mig-${'$'}ID.nft"
 grep -Fq 'G3 migration Daikin MQTT TLS' "/tmp/g3mig-${'$'}ID.nft"; BACKEND=fw4
elif command -v fw3 >/dev/null 2>&1; then
 iptables-save -t nat > "/tmp/g3mig-${'$'}ID.iptables"
 grep -Fq 'G3 migration Daikin HTTPS' "/tmp/g3mig-${'$'}ID.iptables"
 grep -Fq 'G3 migration Daikin MQTT TLS' "/tmp/g3mig-${'$'}ID.iptables"; BACKEND=fw3
else exit 70; fi
printf 'id=%s\nrouter=%s\nphone=%s\nbackend=%s\n' "${'$'}ID" "${'$'}ROUTER" "${'$'}PHONE" "${'$'}BACKEND" > "${'$'}SESSION"
trap - EXIT HUP INT TERM
echo "ACTIVE ${'$'}ID backend=${'$'}BACKEND split-dns=three-daikin-domains"
""".trimIndent() + "\n"
        val r = run(routerIp,user,password,script)
        return Result(r.first,id,r.second)
    }

    fun cleanup(routerIp: String, user: String, password: String, sessionId: String): Result {
        require(validIp(routerIp) && sessionId.matches(Regex("[a-f0-9]{32}")))
        val script = """
set -eu
ID='$sessionId'; SESSION="/root/g3-migration-$sessionId.session"
FWBACK="/root/g3-migration-$sessionId.firewall.bak"; DHCPBACK="/root/g3-migration-$sessionId.dhcp.bak"
FWROLL="/tmp/g3mig-$sessionId.fw.rollback"; DHROLL="/tmp/g3mig-$sessionId.dhcp.rollback"
[ -z "$(uci changes firewall)" ] && [ -z "$(uci changes dhcp)" ]
[ -f "${'$'}SESSION" ] && grep -Fqx "id=${'$'}ID" "${'$'}SESSION"
cp /etc/config/firewall "${'$'}FWROLL"; cp /etc/config/dhcp "${'$'}DHROLL"
rollback() { rc=${'$'}?; if [ "${'$'}rc" -ne 0 ]; then cp "${'$'}FWROLL" /etc/config/firewall; cp "${'$'}DHROLL" /etc/config/dhcp; uci revert firewall || true; uci revert dhcp || true; /etc/init.d/dnsmasq restart || true; /etc/init.d/firewall reload || true; fi; }
trap rollback EXIT HUP INT TERM
for suffix in https mqtt; do
 s="g3mig_${'$'}{ID}_${'$'}suffix"; owner="$(uci -q get firewall.${'$'}s.g3mig_owner || true)"
 if [ -n "${'$'}owner" ]; then [ "${'$'}owner" = "${'$'}ID" ]; uci -q delete firewall.${'$'}s; fi
done
PHONE="$(sed -n 's/^phone=//p' "${'$'}SESSION")"; [ -n "${'$'}PHONE" ]
for d in newlifemulti.daikin-china.com.cn newlifemulti-cdh.daikin-china.com.cn newlifemulti-cdh-core.daikin-china.com.cn; do
 e="/${'$'}d/${'$'}PHONE#1053"; if uci -q get dhcp.@dnsmasq[0].server | grep -Fqx "${'$'}e"; then uci -q del_list dhcp.@dnsmasq[0].server="${'$'}e"; fi
done
uci commit dhcp; uci commit firewall
/etc/init.d/dnsmasq restart; /etc/init.d/firewall reload
for d in newlifemulti.daikin-china.com.cn newlifemulti-cdh.daikin-china.com.cn newlifemulti-cdh-core.daikin-china.com.cn; do
 e="/${'$'}d/${'$'}PHONE#1053"; if uci -q get dhcp.@dnsmasq[0].server | grep -Fqx "${'$'}e"; then exit 75; fi
done
for suffix in https mqtt; do s="g3mig_${'$'}{ID}_${'$'}suffix"; ! uci -q get firewall.${'$'}s >/dev/null 2>&1; done
rm -f "${'$'}SESSION" "${'$'}FWBACK" "${'$'}DHCPBACK" "${'$'}FWROLL" "${'$'}DHROLL" "/tmp/g3mig-${'$'}ID.nft" "/tmp/g3mig-${'$'}ID.iptables"
trap - EXIT HUP INT TERM; echo "CLEANED ${'$'}ID"
""".trimIndent() + "\n"
        val r = run(routerIp,user,password,script)
        return Result(r.first,sessionId,r.second)
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
        session.setUserInfo(PasswordAuth(password))
        session.hostKeyRepository = keys
        session.setConfig("StrictHostKeyChecking","yes")
        session.setConfig("PreferredAuthentications","keyboard-interactive,password")
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