package io.github.doa2011.g3provision

import android.app.*
import android.content.Intent
import android.os.IBinder
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.cert.jcajce.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import javax.net.ssl.*

/** Android-hosted HTTPS compatibility server. OTA is deliberately disabled in this first milestone. */
data class G3FirmwareImage(val bytes:ByteArray,val version:String,val md5:String)

object G3FirmwareValidator {
    fun load(file:File, version:String):G3FirmwareImage {
        require(version.matches(Regex("[A-Za-z0-9_.-]{1,31}"))) { "固件版本号格式无效" }
        val raw=file.readBytes()
        require(raw.size in 32..0x1E0000) { "固件大小不在 32..1966080 字节范围内" }
        require((raw[0].toInt() and 255)==0xE9 && (raw[1].toInt() and 255) in 1..16) { "不是 ESP32 应用镜像（magic/segment count 错误）" }
        require(raw[12]==0.toByte() && raw[13]==0.toByte()) { "固件芯片 ID 不是 ESP32" }
        require(raw.size>=352 && raw.copyOfRange(32,36).contentEquals(byteArrayOf(0x32,0x54,0xcd.toByte(),0xab.toByte()))) { "固件缺少 G3 应用标识" }
        val model="BRY88BBA15G".toByteArray(Charsets.US_ASCII).copyOf(32)
        val product="PHICOMM-DAIKIN-1:full".toByteArray(Charsets.US_ASCII).copyOf(32)
        require(raw.copyOfRange(288,320).contentEquals(model)) { "固件型号不匹配：需要 BRY88BBA15G" }
        require(raw.copyOfRange(320,352).contentEquals(product)) { "固件不是 G3 full application" }
        val md5=MessageDigest.getInstance("MD5").digest(raw).joinToString("") { "%02x".format(it.toInt() and 255) }
        return G3FirmwareImage(raw,version,md5)
    }
}

class G3HttpsServer(port:Int, private val mac:String, private val origin:String, private val ca:ByteArray, ssl:SSLContext, private val firmware:G3FirmwareImage?=null):NanoHTTPD("0.0.0.0",port) {
    private val token=java.util.UUID.randomUUID().toString().replace("-","")+java.util.UUID.randomUUID().toString().take(16)
    init { makeSecure(ssl.serverSocketFactory,null) }
    override fun serve(s:IHTTPSession):Response = try {
        when {
            s.method==Method.GET && s.uri=="/mqtt/root-ca.pem" -> binary(ca)
            s.method==Method.GET && s.uri=="/firmware/bry88-esp32-app.bin" && firmware!=null -> binary(firmware.bytes)
            s.method==Method.GET && s.uri=="/ota/tenant/VRV/device/deviceLogin" -> {
                val p=s.parameters
                if(p["deviceId"]?.firstOrNull()!=mac || p["pwd"]?.firstOrNull()!=stockPassword(mac)) denied()
                else reply(JSONObject().put("errcode",0).put("data",JSONObject().put("token",token)))
            }
            s.method==Method.POST && s.uri=="/jwt/getToken" -> {
                val b=body(s)
                if(b.optString("clientId")!="SENSOR:"+mac || b.optString("password")!=stockPassword(mac)) denied()
                else reply(JSONObject().put("errcode",0).put("data",token))
            }
            s.method==Method.POST && s.uri=="/gateway/getCaCertificateInfo" -> {
                val b=body(s)
                if(b.optString("clientId")!=mac || b.optString("password")!=stockPassword(mac) || b.optString("clientType")!="SENSOR" || b.optString("domainType")!="DEVICE_EMQ") denied()
                else {
                    val md=MessageDigest.getInstance("MD5").digest(ca).joinToString(""){"%02x".format(it)}
                    val d=JSONObject().put("downloadInfo",JSONObject().put("resourcesPath",origin+"/mqtt/root-ca.pem").put("md5",md))
                    reply(JSONObject().put("errcode",0).put("data",d))
                }
            }
            s.method==Method.POST && s.uri=="/ota/tenant/VRV/device/checkUpgrade-json" -> {
                val b=body(s)
                if(s.headers["token"]!=token || b.optString("deviceId")!=mac) denied()
                else {
                    val offer=firmware!=null && b.optString("deviceType")=="SENSOR3_ESP32" && b.optString("firmwareVersion")!=firmware.version
                    val data=JSONObject().put("haveNewVersion",if(offer) 1 else 0)
                    if(offer) data.put("firmware",JSONObject().put("version",firmware!!.version)
                        .put("s3Url",origin+"/firmware/bry88-esp32-app.bin").put("md5",firmware.md5))
                    reply(JSONObject().put("errcode",0).put("data",data))
                }
            }
            else -> newFixedLengthResponse(Response.Status.NOT_FOUND,"application/json","{\"errcode\":1,\"data\":{}}")
        }
    } catch(_:Exception) { newFixedLengthResponse(Response.Status.BAD_REQUEST,"application/json","{\"errcode\":1,\"data\":{}}") }
    private fun body(s:IHTTPSession):JSONObject { val m=HashMap<String,String>();s.parseBody(m);val x=m["postData"]?: "";require(x.toByteArray().size in 1..4096);return JSONObject(x) }
    private fun denied()=newFixedLengthResponse(Response.Status.FORBIDDEN,"application/json","{\"errcode\":1,\"data\":{}}")
    private fun reply(j:JSONObject):Response { val b=j.toString().toByteArray();return newFixedLengthResponse(Response.Status.OK,"application/json",b.inputStream(),b.size.toLong()).apply{addHeader("Cache-Control","no-store")} }
    private fun binary(b:ByteArray):Response=newFixedLengthResponse(Response.Status.OK,"application/octet-stream",b.inputStream(),b.size.toLong()).apply{addHeader("Cache-Control","no-store")}
    companion object {
        fun stockPassword(mac:String):String {
            var crc=0
            mac.chunked(2).forEachIndexed { i,h -> crc=crc xor ((h.toInt(16)+10*(i+1)) and 255);repeat(8){if((crc and 1)!=0)crc=crc xor 0x10811;crc=crc ushr 1};crc=crc and 0xffff }
            return "%04X".format(crc)
        }
    }
}

class G3TlsIdentity(private val service:Service) {
    private val dir=File(service.filesDir,"g3-local").apply{mkdirs()}
    private val pem=File(dir,"ca.pem");private val p12=File(dir,"identity.p12")
    private val hostFile=File(dir,"certificate-host.txt")
    private val pass=("g3-"+service.packageName+"-private").toCharArray()
    data class Result(val ca:ByteArray,val ssl:SSLContext,val keyStorePath:String,val keyStorePassword:String)
    fun load(host:String):Result {
        if(Security.getProvider("BC")==null)Security.addProvider(BouncyCastleProvider())
        if(!pem.exists()||!p12.exists()||!hostFile.exists())create(host)
        require(hostFile.readText().trim()==host) { "手机 IP 已变化；为避免设备 CA 不一致，请固定 DHCP 地址或在重新配网前重置本地证书身份" }
        val ks=KeyStore.getInstance("PKCS12");p12.inputStream().use{ks.load(it,pass)}
        val km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(ks,pass)
        val ssl=SSLContext.getInstance("TLS");ssl.init(km.keyManagers,null,null)
        return Result(pem.readBytes(),ssl,p12.absolutePath,String(pass))
    }
    private fun create(host:String) {
        val kg=KeyPairGenerator.getInstance("RSA");kg.initialize(2048);val kp=kg.generateKeyPair()
        val name=X500Name("CN=newlifemulti.daikin-china.com.cn");val now=System.currentTimeMillis()
        val b=JcaX509v3CertificateBuilder(name,BigInteger(160,SecureRandom()),Date(now-300000),Date(now+30L*86400000),name,kp.public)
        b.addExtension(Extension.subjectAlternativeName,false,GeneralNames(arrayOf(
            GeneralName(GeneralName.dNSName,"newlifemulti.daikin-china.com.cn"),
            GeneralName(GeneralName.dNSName,"newlifemulti-cdh.daikin-china.com.cn"),
            GeneralName(GeneralName.dNSName,"newlifemulti-cdh-core.daikin-china.com.cn"), GeneralName(GeneralName.iPAddress,java.net.InetAddress.getByName(host).hostAddress))))
        b.addExtension(Extension.basicConstraints,true,BasicConstraints(true))
        b.addExtension(Extension.keyUsage,true,KeyUsage(KeyUsage.keyCertSign or KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
        val cert:JcaX509CertificateConverter=JcaX509CertificateConverter().setProvider("BC")
        val x:X509Certificate=cert.getCertificate(b.build(JcaContentSignerBuilder("SHA256withRSA").build(kp.private)));x.verify(kp.public)
        val ks=KeyStore.getInstance("PKCS12");ks.load(null,pass);ks.setKeyEntry("g3",kp.private,pass,arrayOf(x));p12.outputStream().use{ks.store(it,pass)}
        pem.writeText("-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,byteArrayOf(10)).encodeToString(x.encoded)+"\n-----END CERTIFICATE-----\n")
        hostFile.writeText(host)
    }
}

/** Keeps the local HTTPS endpoint alive while Android backgrounds the UI. */
class G3MigrationService:Service() {
    private var server:G3HttpsServer?=null
    private var broker:G3MqttBroker?=null
    private var firmware:G3FirmwareImage?=null
    private var cpuLock:android.os.PowerManager.WakeLock?=null
    private var wifiLock:android.net.wifi.WifiManager.WifiLock?=null
    override fun onBind(i:Intent?):IBinder?=null
    override fun onStartCommand(i:Intent?,flags:Int,startId:Int):Int {
        if (i?.getBooleanExtra(EXTRA_TRIGGER_OTA,false)==true) {
            val version=i.getStringExtra(EXTRA_VERSION).orEmpty()
            val ok=firmware!=null && firmware?.version==version && broker?.triggerEsp32Upgrade(version)==true
            getSharedPreferences("g3",0).edit().putString("ota_state",if(ok) "ESP32 OTA command sent once" else "OTA blocked: firmware missing, gateway replies incomplete, or device not subscribed").apply()
            return START_NOT_STICKY
        }
        val channel="g3-local-migration"
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(channel,"G3 迁移服务",NotificationManager.IMPORTANCE_LOW))
        val n=Notification.Builder(this,channel).setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle("G3 本地 HTTPS 服务").setContentText("HTTPS 8443 + MQTT TLS 8883 服务运行中").setOngoing(true).build()
        startForeground(41,n)
        try {
            val pm=getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
            cpuLock=pm.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK,"G3Migration:CPU").apply{setReferenceCounted(false);acquire()}
            val wm=applicationContext.getSystemService(android.content.Context.WIFI_SERVICE) as android.net.wifi.WifiManager
            @Suppress("DEPRECATION")
            wifiLock=wm.createWifiLock(android.net.wifi.WifiManager.WIFI_MODE_FULL_HIGH_PERF,"G3Migration:WiFi").apply{setReferenceCounted(false);acquire()}
            val mac=(i?.getStringExtra(EXTRA_MAC)?: "").replace(":","").replace("-","").uppercase()
            require(Regex("[0-9A-F]{12}").matches(mac)){"请输入 G3 Wi-Fi STA MAC"}
            val origin=i?.getStringExtra(EXTRA_ORIGIN)?: ""
            require(origin.startsWith("https://")){"origin 必须为 https:// 开头"}
            val host=java.net.URI(origin).host ?: throw IllegalArgumentException("origin host invalid")
            val id=G3TlsIdentity(this).load(host)
            val firmwarePath=i?.getStringExtra(EXTRA_FIRMWARE_PATH).orEmpty()
            val version=i?.getStringExtra(EXTRA_VERSION).orEmpty()
            firmware=if(firmwarePath.isNotBlank()) G3FirmwareValidator.load(File(firmwarePath),version) else null
            server?.stop();server=G3HttpsServer(8443,mac,origin,id.ca,id.ssl,firmware) { broker?.allGatewayRepliesObserved()==true };server?.start(NanoHTTPD.SOCKET_READ_TIMEOUT,false)
            val gateway=(i?.getStringExtra(EXTRA_GATEWAY)?:"020000000001").replace(":","").replace("-","").uppercase()
            require(Regex("[0-9A-F]{12}").matches(gateway)){"虚拟网关 MAC 无效"}
            broker?.stop();getSharedPreferences("g3",0).edit().putStringSet("gateway_acks", emptySet()).apply();broker=G3MqttBroker(mac,gateway,id.ssl) { topics -> getSharedPreferences("g3",0).edit().putStringSet("gateway_acks", HashSet(topics)).apply() };broker?.start()
            getSharedPreferences("g3",0).edit().putString("service_state","HTTPS 8443 + MQTT TLS 8883 running").apply()
        } catch(e:Exception) {
            getSharedPreferences("g3",0).edit().putString("service_state","ERROR: "+(e.message?:e.javaClass.simpleName)).apply()
            stopSelf()
        }
        return START_NOT_STICKY
    }
    override fun onDestroy(){broker?.stop();broker=null;server?.stop();server=null;try{if(cpuLock?.isHeld==true)cpuLock?.release()}catch(_:Exception){};try{if(wifiLock?.isHeld==true)wifiLock?.release()}catch(_:Exception){};cpuLock=null;wifiLock=null;super.onDestroy()}
    companion object {
        const val EXTRA_MAC="g3_device_mac"
        const val EXTRA_ORIGIN="g3_origin"
        const val EXTRA_GATEWAY="g3_gateway"
        const val EXTRA_FIRMWARE_PATH="g3_firmware_path"
        const val EXTRA_VERSION="g3_firmware_version"
        const val EXTRA_TRIGGER_OTA="g3_trigger_ota"
    }
}
