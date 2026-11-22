package io.github.doa2011.g3provision

import io.moquette.broker.Server
import io.moquette.interception.InterceptHandler
import io.moquette.interception.messages.*
import io.netty.buffer.Unpooled
import io.netty.handler.codec.mqtt.MqttMessageBuilders
import io.netty.handler.codec.mqtt.MqttQoS
import io.netty.util.CharsetUtil
import io.netty.util.ReferenceCountUtil
import org.json.JSONObject
import java.util.Properties
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Embedded TLS MQTT broker plus the five bounded factory-gateway compatibility acknowledgements. */
class G3MqttBroker(
    private val mac: String,
    private val gatewayMac: String,
    private val keyStorePath: String,
    private val keyStorePassword: String,
    private val weatherCode: Int = 1
) {
    private val server = Server()
    private val executor = Executors.newSingleThreadScheduledExecutor()
    @Volatile private var running = false

    fun start() {
        val p = Properties().apply {
            setProperty("host", "0.0.0.0")
            setProperty("port", "disabled")
            setProperty("ssl_port", "18883")
            setProperty("jks_path", keyStorePath)
            setProperty("key_store_type", "PKCS12")
            setProperty("key_store_password", keyStorePassword)
            setProperty("key_manager_password", keyStorePassword)
            setProperty("ssl_provider", "JDK")
            setProperty("allow_anonymous", "true")
            setProperty("persistence_enabled", "false")
            setProperty("telemetry_enabled", "false")
        }
        server.startServer(p, listOf(GatewayHandler()))
        running = true
    }

    fun stop() {
        running = false
        try { server.stopServer() } catch (_: Exception) {}
        executor.shutdownNow()
    }

    fun isRunning() = running

    private inner class GatewayHandler : InterceptHandler {
        override fun getID() = "g3-android-gateway"
        override fun getInterceptedMessageTypes(): Array<Class<*>> = arrayOf(InterceptPublishMessage::class.java)
        override fun onConnect(msg: InterceptConnectMessage) {}
        override fun onDisconnect(msg: InterceptDisconnectMessage) {}
        override fun onConnectionLost(msg: InterceptConnectionLostMessage) {}
        override fun onSubscribe(msg: InterceptSubscribeMessage) {}
        override fun onUnsubscribe(msg: InterceptUnsubscribeMessage) {}
        override fun onMessageAcknowledged(msg: InterceptAcknowledgedMessage) {}
        override fun onSessionLoopError(error: Throwable) {}
        override fun onPublish(msg: InterceptPublishMessage) {
            val topic = msg.topicName
            val payload = try { msg.payload().toString(CharsetUtil.UTF_8) } catch (_: Exception) { "" }
            ReferenceCountUtil.release(msg.message())
            if (!running || payload.length > 8192) return
            val responseTopic = responseTopic(topic) ?: return
            executor.schedule({ acknowledge(topic, responseTopic, payload) }, 1500, TimeUnit.MILLISECONDS)
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

    private fun acknowledge(requestTopic: String, responseTopic: String, raw: String) {
        if (!running) return
        try {
            val request = JSONObject(raw)
            val token = request.optString("client_token")
            if (token.isBlank() || token.length > 128) return
            val data = request.optJSONObject("data") ?: JSONObject()
            if (requestTopic.endsWith("upload_snapshot")) {
                val physicsMac = data.optJSONObject("physics")?.optString("mac")
                if (physicsMac != mac) return
            } else if (data.optString("terminal_mac", gatewayMac) != gatewayMac) return

            val responseData = when {
                requestTopic.endsWith("/get_weather") -> JSONObject()
                    .put("temperature", -100).put("humidity", 200)
                    .put("pm25", -100).put("weatherCode", weatherCode)
                requestTopic.endsWith("/get_filter_sensor3") -> JSONObject().put("filter_infos", org.json.JSONArray())
                requestTopic.endsWith("/get_error_sensor3") -> JSONObject().put("error_infos", org.json.JSONArray())
                else -> JSONObject()
            }
            val response = JSONObject().put("code", 0).put("data", responseData)
                .put("client_token", token).put("timestamp", System.currentTimeMillis()).toString()
            val message = MqttMessageBuilders.publish().topicName(responseTopic)
                .qos(MqttQoS.AT_MOST_ONCE)
                .payload(Unpooled.copiedBuffer(response, CharsetUtil.UTF_8)).build()
            server.internalPublish(message, "g3-android-gateway")
        } catch (_: Exception) {
            // Invalid or unrelated messages are deliberately ignored.
        }
    }
}
