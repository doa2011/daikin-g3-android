package io.github.doa2011.g3provision

import org.json.JSONObject
import org.json.JSONArray
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket

/**
 * Small MQTT 3.1.1 TLS broker for the bounded G3 migration workflow.
 * Supports CONNECT, PUBLISH QoS 0/1, SUBSCRIBE, UNSUBSCRIBE, PINGREQ and DISCONNECT.
 * It intentionally does not expose a general-purpose broker or enable OTA by itself.
 */
class G3MqttBroker(
    private val mac: String,
    private val gatewayMac: String,
    private val sslContext: SSLContext,
    private val port: Int = 8883,
    private val weatherCode: Int = 1,
    private val onAckState: (Set<String>) -> Unit = {}
) {
    @Volatile private var running = false
    private var listener: SSLServerSocket? = null
    private val workers = Executors.newCachedThreadPool()
    private val delayed = Executors.newSingleThreadScheduledExecutor()
    private val clients = ConcurrentHashMap.newKeySet<Client>()
    private val acknowledged = ConcurrentHashMap.newKeySet<String>()

    fun start() {
        if (running) return
        listener = sslContext.serverSocketFactory.createServerSocket(port) as SSLServerSocket
        listener!!.needClientAuth = false
        listener!!.enabledProtocols = listener!!.supportedProtocols.filter { it == "TLSv1.2" || it == "TLSv1.3" }.toTypedArray()
        running = true
        workers.execute {
            while (running) {
                try {
                    val socket = listener!!.accept()
                    socket.soTimeout = 120000
                    val client = Client(socket)
                    clients.add(client)
                    workers.execute { client.run() }
                } catch (_: Exception) {
                    if (running) { /* accept loop remains available for the next connection */ }
                }
            }
        }
    }

    fun stop() {
        running = false
        try { listener?.close() } catch (_: Exception) {}
        clients.toList().forEach { it.close() }
        workers.shutdownNow()
        delayed.shutdownNow()
    }


    fun triggerEsp32Upgrade(version: String): Boolean {
        if (!allGatewayRepliesObserved() || !version.matches(Regex("[A-Za-z0-9_.-]{1,31}"))) return false
        val topic = "SENSOR/" + mac + "/mqtt/service/ota"
        val payload = JSONObject()
            .put("client_token", "iotcloud-" + java.util.UUID.randomUUID().toString().replace("-", "").take(16))
            .put("data", JSONObject().put("upgrade_method", 1).put("upgrade_info",
                JSONArray().put(JSONObject().put("device_type", "SENSOR3_ESP32").put("to_version", version))))
            .toString()
        val recipients = clients.filter { it.accepts(topic) }
        if (recipients.isEmpty()) return false
        recipients.forEach { it.sendPublish(topic, payload) }
        return true
    }

    fun isRunning() = running
    fun acknowledgedTopics(): Set<String> = acknowledged.toSet()
    fun allGatewayRepliesObserved(): Boolean = acknowledged.size == 5

    private inner class Client(private val socket: Socket) {
        private val input = DataInputStream(socket.getInputStream())
        private val output = DataOutputStream(socket.getOutputStream())
        private val subscriptions = ConcurrentHashMap.newKeySet<String>()
        @Volatile private var active = true
        var clientId: String = "unknown"

        fun run() {
            try {
                while (active && running) {
                    val header = input.read()
                    if (header < 0) break
                    val remaining = readRemainingLength(input)
                    if (remaining < 0 || remaining > 1024 * 1024) break
                    val body = ByteArray(remaining)
                    input.readFully(body)
                    handle(header, body)
                }
            } catch (_: EOFException) {
            } catch (_: Exception) {
            } finally { close() }
        }

        private fun handle(header: Int, body: ByteArray) {
            when ((header ushr 4) and 0x0f) {
                1 -> connect(body)
                3 -> publish(header, body)
                8 -> subscribe(body)
                10 -> unsubscribe(body)
                12 -> writePacket(0xD0, byteArrayOf())
                14 -> close()
                else -> { /* unsupported MQTT control packets are ignored */ }
            }
        }

        private fun connect(body: ByteArray) {
            val c = Cursor(body)
            val protocol = c.readUtf8()
            val level = c.readByte()
            c.readByte() // connect flags
            c.readUnsignedShort() // keep alive
            if (protocol != "MQTT" || (level != 4 && level != 3)) {
                writePacket(0x20, byteArrayOf(0, 1)); close(); return
            }
            clientId = c.readUtf8()
            // Remaining will/user/password fields are intentionally ignored; upstream broker permits anonymous.
            writePacket(0x20, byteArrayOf(0, 0))
        }

        private fun subscribe(body: ByteArray) {
            val c = Cursor(body)
            val packetId = c.readUnsignedShort()
            val granted = ArrayList<Byte>()
            while (c.remaining() > 0) {
                val topic = c.readUtf8()
                val qos = c.readByte()
                if (topic.isNotBlank() && qos in 0..1) {
                    subscriptions.add(topic)
                    granted.add(qos.toByte())
                } else granted.add(0x80.toByte())
            }
            val ack = byteArrayOf((packetId ushr 8).toByte(), packetId.toByte()) + granted.toByteArray()
            writePacket(0x90, ack)
        }

        private fun unsubscribe(body: ByteArray) {
            val c = Cursor(body)
            val packetId = c.readUnsignedShort()
            while (c.remaining() > 0) subscriptions.remove(c.readUtf8())
            writePacket(0xB0, byteArrayOf((packetId ushr 8).toByte(), packetId.toByte()))
        }

        private fun publish(header: Int, body: ByteArray) {
            val qos = (header ushr 1) and 0x03
            if (qos > 1) return
            val c = Cursor(body)
            val topic = c.readUtf8()
            val packetId = if (qos == 1) c.readUnsignedShort() else 0
            val payload = c.readBytes(c.remaining())
            if (qos == 1) writePacket(0x40, byteArrayOf((packetId ushr 8).toByte(), packetId.toByte()))
            val responseTopic = responseTopic(topic) ?: return
            if (payload.size > 8192) return
            val raw = String(payload, StandardCharsets.UTF_8)
            delayed.schedule({ acknowledge(topic, responseTopic, raw) }, 1500, TimeUnit.MILLISECONDS)
        }

        fun sendPublish(topic: String, payload: String) {
            val topicBytes = topic.toByteArray(StandardCharsets.UTF_8)
            val data = payload.toByteArray(StandardCharsets.UTF_8)
            val body = byteArrayOf((topicBytes.size ushr 8).toByte(), topicBytes.size.toByte()) + topicBytes + data
            synchronized(output) {
                writePacketLocked(0x30, body)
            }
        }

        private fun writePacket(header: Int, body: ByteArray) {
            synchronized(output) { writePacketLocked(header, body) }
        }

        private fun writePacketLocked(header: Int, body: ByteArray) {
            if (!active) return
            output.writeByte(header)
            writeRemainingLength(output, body.size)
            output.write(body)
            output.flush()
        }

        fun close() {
            if (!active) return
            active = false
            clients.remove(this)
            try { socket.close() } catch (_: Exception) {}
        }

        fun accepts(topic: String): Boolean = subscriptions.any { topicMatches(it, topic) }
    }

    private fun acknowledge(requestTopic: String, responseTopic: String, raw: String) {
        if (!running) return
        try {
            val request = JSONObject(raw)
            val token = request.optString("client_token")
            if (token.isBlank() || token.length > 128) return
            val data = request.optJSONObject("data") ?: JSONObject()
            if (requestTopic.endsWith("upload_snapshot")) {
                if (data.optJSONObject("physics")?.optString("mac") != mac) return
            } else if (data.optString("terminal_mac", gatewayMac) != gatewayMac) return

            val responseData = when {
                requestTopic.endsWith("/get_weather") -> JSONObject()
                    .put("temperature", -100).put("humidity", 200)
                    .put("pm25", -100).put("weatherCode", weatherCode)
                requestTopic.endsWith("/get_filter_sensor3") -> JSONObject().put("filter_infos", JSONArray())
                requestTopic.endsWith("/get_error_sensor3") -> JSONObject().put("error_infos", JSONArray())
                else -> JSONObject()
            }
            val response = JSONObject().put("code", 0).put("data", responseData)
                .put("client_token", token).put("timestamp", System.currentTimeMillis()).toString()
            val recipients = clients.filter { it.accepts(responseTopic) }
            if (recipients.isNotEmpty()) {
                recipients.forEach { it.sendPublish(responseTopic, response) }
                acknowledged.add(responseTopic)
                onAckState(acknowledgedTopics())
            }
        } catch (_: Exception) {
            // Ignore malformed or unrelated factory messages.
        }
    }

    private fun responseTopic(topic: String): String? {
        val root = "SENSOR/" + mac
        return when {
            topic == root + "/mqtt/event/upload_snapshot" -> root + "/mqtt/event_response/snapshot_upload"
            topic == root + "/mqtt/event/get_weather" -> root + "/mqtt/event_response/get_weather"
            topic == root + "/IPBOX/" + gatewayMac + "/mqtt/event/login_ipbox" ->
                root + "/IPBOX/" + gatewayMac + "/mqtt/event_response/login_ipbox"
            topic == "IPBOX/" + gatewayMac + "/" + root + "/mqtt/service/get_filter_sensor3" ->
                "IPBOX/" + gatewayMac + "/" + root + "/mqtt/service_response/get_filter_sensor3"
            topic == "IPBOX/" + gatewayMac + "/" + root + "/mqtt/service/get_error_sensor3" ->
                "IPBOX/" + gatewayMac + "/" + root + "/mqtt/service_response/get_error_sensor3"
            else -> null
        }
    }

    private fun topicMatches(filter: String, topic: String): Boolean {
        val f = filter.split("/")
        val t = topic.split("/")
        var i = 0
        while (i < f.size) {
            if (f[i] == "#") return i == f.lastIndex
            if (i >= t.size || (f[i] != "+" && f[i] != t[i])) return false
            i++
        }
        return i == t.size
    }

    private class Cursor(private val bytes: ByteArray) {
        private var at = 0
        fun remaining() = bytes.size - at
        fun readByte(): Int { require(remaining() >= 1); return bytes[at++].toInt() and 255 }
        fun readUnsignedShort(): Int { val a=readByte();val b=readByte();return (a shl 8) or b }
        fun readBytes(n:Int):ByteArray { require(n>=0 && remaining()>=n);return bytes.copyOfRange(at,at+n).also{at+=n} }
        fun readUtf8():String { val n=readUnsignedShort();return String(readBytes(n),StandardCharsets.UTF_8) }
    }

    private fun readRemainingLength(input: DataInputStream): Int {
        var multiplier = 1
        var value = 0
        var count = 0
        do {
            val digit = input.readUnsignedByte()
            value += (digit and 127) * multiplier
            multiplier *= 128
            count++
            if (count > 4) return -1
            if ((digit and 128) == 0) return value
        } while (true)
    }

    private fun writeRemainingLength(out: DataOutputStream, length: Int) {
        var value = length
        do {
            var digit = value % 128
            value /= 128
            if (value > 0) digit = digit or 128
            out.writeByte(digit)
        } while (value > 0)
    }
}
