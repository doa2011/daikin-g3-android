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
    data class Result(val output: String, val fingerprint: String)

    private class PinRepository(private val expected: String) : HostKeyRepository {
        var observed = ""
        override fun check(host: String, key: ByteArray): Int {
            observed = "SHA256:" + Base64.getEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(key))
            return if (expected.isNotBlank() && expected == observed) 0 else 1
        }
        override fun getHostKey(): Array<HostKey> = emptyArray()
        override fun getHostKey(host: String, type: String): Array<HostKey> = emptyArray()
        override fun add(hostkey: HostKey, ui: UserInfo?) {}
        override fun remove(host: String, type: String) {}
        override fun remove(host: String, type: String, key: ByteArray) {}
        override fun getKnownHostsRepositoryID(): String = "G3 pinned host key"
    }

    fun apply(host: String, user: String, password: String, fingerprint: String,
              routerIp: String, phoneIp: String, g3Ip: String) =
        run(host,user,password,fingerprint,routerIp,phoneIp,g3Ip,true)

    fun remove(host: String, user: String, password: String, fingerprint: String,
               routerIp: String, phoneIp: String, g3Ip: String) =
        run(host,user,password,fingerprint,routerIp,phoneIp,g3Ip,false)

    private fun run(host: String, user: String, password: String, fingerprint: String,
                    routerIp: String, phoneIp: String, g3Ip: String, enable: Boolean): Result {
        fun ip(v:String) = v.matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}")) &&
            v.split(".").all { it.toInt() in 0..255 }
        require(ip(host) && ip(routerIp) && ip(phoneIp) && ip(g3Ip)) { "IPv4 地址无效" }
        require(user.isNotBlank() && password.isNotEmpty()) { "SSH 用户名或密码为空" }
        val pin=PinRepository(fingerprint.trim())
        val jsch=JSch()
        val session=jsch.getSession(user,host,22)
        session.setPassword(password)
        session.hostKeyRepository=pin
        session.setConfig("StrictHostKeyChecking","yes")
        try {
            session.connect(12000)
            val channel=session.openChannel("exec") as com.jcraft.jsch.ChannelExec
            channel.setCommand("sh -s")
            val out=ByteArrayOutputStream(); val err=ByteArrayOutputStream()
            channel.setOutputStream(out); channel.setErrStream(err)
            channel.connect(8000)
            val script=if(enable) applyScript(routerIp,phoneIp,g3Ip) else removeScript()
            channel.outputStream.use { it.write(script.toByteArray(StandardCharsets.UTF_8)); it.flush() }
            val deadline=System.currentTimeMillis()+20000
            while(!channel.isClosed && System.currentTimeMillis()<deadline) Thread.sleep(100)
            if(!channel.isClosed) { channel.disconnect(); error("OpenWrt 命令执行超时") }
            val code=channel.exitStatus; channel.disconnect()
            val output=out.toString("UTF-8")+err.toString("UTF-8")
            check(code==0) { "OpenWrt 配置失败（退出码 $code）：$output" }
            return Result(output.ifBlank { if(enable) "G3 专用规则已启用" else "G3 专用规则已撤销" },pin.observed)
        } catch(e:Exception) {
            if(e is JSchException && pin.observed.isNotBlank() && fingerprint.trim()!=pin.observed)
                throw IllegalStateException("请核对路由器主机密钥指纹后重试：${pin.observed}")
            throw e
        } finally { session.disconnect() }
    }

    private fun applyScript(router:String, phone:String, g3:String):String {
        val p="'$phone'"; val g="'$g3'"; val r="'$router'"
        return """
set -eu
mkdir -p /root/g3-migration-backup
[ -f /root/g3-migration-backup/firewall.first ] || cp /etc/config/firewall /root/g3-migration-backup/firewall.first
for s in g3mig_dns_udp g3mig_dns_tcp g3mig_https g3mig_mqtt; do uci -q delete firewall.${'
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name='G3 migration DNS UDP'
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=53
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=5353
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name='G3 migration DNS TCP'
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=53
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=5353
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name='G3 migration HTTPS'
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=443
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=8443
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name='G3 migration MQTT TLS'
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=8883
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=18883
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo 'G3-only migration redirects installed.'
""".trimIndent()+"\n"
    }

    private fun removeScript()="""
set -eu
for s in g3mig_dns_udp g3mig_dns_tcp g3mig_https g3mig_mqtt; do uci -q delete firewall.$s || true; done
uci commit firewall
/etc/init.d/firewall reload
echo 'Only G3 migration redirects removed; unrelated firewall settings preserved.'
""".trimIndent()+"\n"
}
}s || true; done
uci set firewall.g3mig_dns_udp=redirect
uci set firewall.g3mig_dns_udp.name='G3 migration DNS UDP'
uci set firewall.g3mig_dns_udp.src=lan
uci set firewall.g3mig_dns_udp.src_ip=$g
uci set firewall.g3mig_dns_udp.src_dport=53
uci set firewall.g3mig_dns_udp.dest=lan
uci set firewall.g3mig_dns_udp.dest_ip=$p
uci set firewall.g3mig_dns_udp.dest_port=5353
uci set firewall.g3mig_dns_udp.proto=udp
uci set firewall.g3mig_dns_udp.target=DNAT
uci set firewall.g3mig_dns_tcp=redirect
uci set firewall.g3mig_dns_tcp.name='G3 migration DNS TCP'
uci set firewall.g3mig_dns_tcp.src=lan
uci set firewall.g3mig_dns_tcp.src_ip=$g
uci set firewall.g3mig_dns_tcp.src_dport=53
uci set firewall.g3mig_dns_tcp.dest=lan
uci set firewall.g3mig_dns_tcp.dest_ip=$p
uci set firewall.g3mig_dns_tcp.dest_port=5353
uci set firewall.g3mig_dns_tcp.proto=tcp
uci set firewall.g3mig_dns_tcp.target=DNAT
uci set firewall.g3mig_https=redirect
uci set firewall.g3mig_https.name='G3 migration HTTPS'
uci set firewall.g3mig_https.src=lan
uci set firewall.g3mig_https.src_ip=$g
uci set firewall.g3mig_https.src_dip=$r
uci set firewall.g3mig_https.src_dport=443
uci set firewall.g3mig_https.dest=lan
uci set firewall.g3mig_https.dest_ip=$p
uci set firewall.g3mig_https.dest_port=8443
uci set firewall.g3mig_https.proto=tcp
uci set firewall.g3mig_https.target=DNAT
uci set firewall.g3mig_mqtt=redirect
uci set firewall.g3mig_mqtt.name='G3 migration MQTT TLS'
uci set firewall.g3mig_mqtt.src=lan
uci set firewall.g3mig_mqtt.src_ip=$g
uci set firewall.g3mig_mqtt.src_dip=$r
uci set firewall.g3mig_mqtt.src_dport=8883
uci set firewall.g3mig_mqtt.dest=lan
uci set firewall.g3mig_mqtt.dest_ip=$p
uci set firewall.g3mig_mqtt.dest_port=18883
uci set firewall.g3mig_mqtt.proto=tcp
uci set firewall.g3mig_mqtt.target=DNAT
uci commit firewall
/etc/init.d/firewall reload
echo 'G3-only migration redirects installed.'
""".trimIndent()+"\n"
    }

    private fun removeScript()="""
set -eu
for s in g3mig_dns_udp g3mig_dns_tcp g3mig_https g3mig_mqtt; do uci -q delete firewall.$s || true; done
uci commit firewall
/etc/init.d/firewall reload
echo 'Only G3 migration redirects removed; unrelated firewall settings preserved.'
""".trimIndent()+"\n"
}
