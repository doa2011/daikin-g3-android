package io.github.doa2011.g3provision

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicBoolean

/** Small split-DNS responder for one G3 client, exposed only on the LAN via router DNAT. */
class DnsRedirectServer(
    private val upstreamIp: String,
    private val syntheticARecordIp: String,
    private val port: Int = MigrationPorts.DNS,
    private val onDiagnostic: (String) -> Unit = {}
) {
    private val running = AtomicBoolean(false)
    private var udp: DatagramSocket? = null
    private var tcp: ServerSocket? = null
    private val names = setOf(
        "newlifemulti.daikin-china.com.cn",
        "newlifemulti-cdh.daikin-china.com.cn",
        "newlifemulti-cdh-core.daikin-china.com.cn"
    )

    @Synchronized fun start() {
        check(running.compareAndSet(false, true)) { "DNS 服务已经启动" }
        try {
            udp = DatagramSocket(port).apply { soTimeout = 1000 }
            tcp = ServerSocket(port).apply { soTimeout = 1000 }
            val u = requireNotNull(udp)
            val t = requireNotNull(tcp)
            Thread({ udpLoop(u) }, "g3-dns-udp").start()
            Thread({ tcpLoop(t) }, "g3-dns-tcp").start()
        } catch (e: Exception) {
            stop()
            throw e
        }
    }

    @Synchronized fun stop() {
        running.set(false)
        udp?.close()
        tcp?.close()
        udp = null
        tcp = null
    }

    private fun udpLoop(socket: DatagramSocket) {
        try {
            val buffer = ByteArray(4096)
            while (running.get()) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val query = packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
                    val response = answerOrForward(query, false)
                    socket.send(DatagramPacket(response, response.size, packet.address, packet.port))
                } catch (_: SocketTimeoutException) {
                } catch (e: Exception) {
                    // A malformed packet or upstream timeout must not terminate the listener.
                }
            }
        } finally { socket.close() }
    }

    private fun tcpLoop(server: ServerSocket) {
        try {
            while (running.get()) {
                try {
                    val client = server.accept()
                    try {
                        client.use { s ->
                            s.soTimeout = 5000
                            val input = DataInputStream(s.getInputStream())
                            val output = DataOutputStream(s.getOutputStream())
                            val length = input.readUnsignedShort()
                            if (length !in 12..4096) return@use
                            val query = ByteArray(length); input.readFully(query)
                            val response = answerOrForward(query, true)
                            output.writeShort(response.size); output.write(response); output.flush()
                        }
                    } catch (_: Exception) { client.close() }
                } catch (_: SocketTimeoutException) {
                }
            }
        } catch (_: java.net.SocketException) {
        } finally { server.close() }
    }

    private fun diag(message: String) { try { onDiagnostic(message) } catch (_: Exception) {} }

    internal fun answerOrForward(query: ByteArray, tcpMode: Boolean): ByteArray {
        val transport = if (tcpMode) "TCP" else "UDP"
        val q = parseQuestion(query) ?: run {
            diag("DNS ERROR transport=$transport invalid-question")
            throw IllegalArgumentException("Invalid DNS question")
        }
        diag("DNS QUERY transport=$transport type=${q.type} target=${q.name in names}")
        if (q.name in names && (q.type == 1 || q.type == 28)) {
            val header = query.copyOfRange(0, 12)
            header[2] = ((header[2].toInt() or 0x80) and 0xff).toByte()
            header[3] = ((header[3].toInt() or 0x80) and 0xff).toByte()
            header[6] = 0; header[7] = if (q.type == 1) 1 else 0
            header[8] = 0; header[9] = 0; header[10] = 0; header[11] = 0
            val answer = if (q.type == 1) {
                val ip = InetAddress.getByName(syntheticARecordIp).address
                require(ip.size == 4) { "合成 DNS 地址必须是 IPv4" }
                byteArrayOf(0xC0.toByte(), 0x0C, 0, 1, 0, 1, 0, 0, 0, 20, 0, 4) + ip
            } else byteArrayOf() // Suppress AAAA so the stock client cannot bypass the IPv4 migration endpoint.
            diag("DNS ${if (q.type == 1) "REDIRECT" else "AAAA-SUPPRESS"} transport=$transport domain=${q.name}")
            return header + query.copyOfRange(12, q.end) + answer
        }
        return try {
            forward(query, tcpMode).also { diag("DNS FORWARD transport=$transport bytes=${it.size}") }
        } catch (e: Exception) {
            diag("DNS ERROR transport=$transport type=${e.javaClass.simpleName}")
            throw e
        }
    }

    private data class Question(val name: String, val type: Int, val end: Int)

    private fun parseQuestion(data: ByteArray): Question? {
        if (data.size < 17 || data[4].toInt() != 0 || data[5].toInt() != 1 || (data[2].toInt() and 0x80) != 0) return null
        var p = 12
        val labels = mutableListOf<String>()
        while (p < data.size) {
            val n = data[p++].toInt() and 255
            if (n == 0) break
            if (n > 63 || p + n > data.size) return null
            labels += String(data, p, n, Charsets.US_ASCII).lowercase()
            p += n
        }
        if (p + 4 > data.size) return null
        val type = ((data[p].toInt() and 255) shl 8) or (data[p + 1].toInt() and 255)
        return Question(labels.joinToString("."), type, p + 4)
    }

    private fun forward(query: ByteArray, tcpMode: Boolean): ByteArray {
        if (tcpMode) {
            Socket().use { socket ->
                socket.connect(java.net.InetSocketAddress(upstreamIp, 53), 2500)
                socket.soTimeout = 4000
                val out = DataOutputStream(socket.getOutputStream())
                out.writeShort(query.size); out.write(query); out.flush()
                val input = DataInputStream(socket.getInputStream())
                val length = input.readUnsignedShort()
                require(length in 12..4096)
                return ByteArray(length).also { input.readFully(it) }
            }
        }
        DatagramSocket().use { socket ->
            socket.soTimeout = 4000
            socket.send(DatagramPacket(query, query.size, InetAddress.getByName(upstreamIp), 53))
            val buffer = ByteArray(4096)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            return packet.data.copyOfRange(packet.offset, packet.offset + packet.length)
        }
    }
}
