package io.github.doa2011.g3provision

import android.app.*
import android.content.Intent
import android.os.IBinder
import fi.iki.elonen.NanoHTTPD
import org.json.JSONObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x509.KeyPurposeId
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

/** Android-hosted HTTPS compatibility server with a verified, optional G3 ESP32 OTA image. */
data class G3FirmwareImage(val bytes:ByteArray,val version:String,val md5:String,val sha256:String)

object G3FirmwareValidator {
    const val BUNDLED_OTA_VERSION = "V99.00.00"
    private const val BUNDLED_ASSET = "g3/daikin_BRY88BBA15G.ota.bin.raw"

    fun load(file:File, version:String, expectedSha256:String?=null):G3FirmwareImage {
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
        val sha256=MessageDigest.getInstance("SHA-256").digest(raw).joinToString("") { "%02x".format(it.toInt() and 255) }
        if(expectedSha256!=null) require(sha256.equals(expectedSha256,true)) { "固件 SHA256 与内置发布清单不一致" }
        return G3FirmwareImage(raw,version,md5,sha256)
    }

    fun loadBundled(context:android.content.Context):Pair<File,G3FirmwareImage> {
        val props=java.util.Properties()
        context.assets.open("g3/firmware.properties").use { props.load(it) }
        val release=props.getProperty("release") ?: error("缺少固件发布版本")
        val artifact=props.getProperty("artifact") ?: error("缺少固件文件名")
        val version=props.getProperty("ota_version") ?: error("缺少 OTA 版本标签")
        val model=props.getProperty("device_model") ?: error("缺少固件型号")
        val deviceType=props.getProperty("device_type") ?: error("缺少设备类型")
        val variant=props.getProperty("variant") ?: error("缺少固件变体")
        val expectedSize=props.getProperty("size")?.toLongOrNull() ?: error("固件大小元数据无效")
        val expectedSha=props.getProperty("sha256") ?: error("缺少固件 SHA256")
        require(release=="v1.0.0-rc.7" && artifact=="daikin_BRY88BBA15G.ota.bin.raw" &&
            model=="BRY88BBA15G" && deviceType=="SENSOR3_ESP32" && variant=="full") {
            "内置固件发布信息与目标设备不匹配"
        }
        val target=File(context.filesDir,"g3-local/$artifact")
        target.parentFile?.mkdirs()
        if(!target.exists() || target.length()!=expectedSize) {
            val tmp=File(target.parentFile,target.name+".tmp")
            context.assets.open(BUNDLED_ASSET).use { input -> tmp.outputStream().use { output -> input.copyTo(output) } }
            require(tmp.length()==expectedSize) { "内置固件文件大小不匹配" }
            if(target.exists()) target.delete()
            require(tmp.renameTo(target)) { "无法写入内置固件缓存" }
        }
        val image=load(target,version,expectedSha)
        require(image.bytes.size.toLong()==expectedSize) { "固件大小与发布清单不一致" }
        return target to image
    }
}

class G3HttpsServer(port:Int, private val mac:String, private val origin:String, private val ca:ByteArray, ssl:SSLContext, private val firmware:G3FirmwareImage?=null, private val onDiagnostic:(String)->Unit={}, private val updateReady:()->Boolean={false}):NanoHTTPD("0.0.0.0",port) {
    private val token=java.util.UUID.randomUUID().toString().replace("-","")+java.util.UUID.randomUUID().toString().take(16)
    init { makeSecure(ssl.serverSocketFactory,null) }
    override fun serve(s:IHTTPSession):Response {
        val response = handleRequest(s)
        val endpoint = when (s.uri) {
            "/mqtt/root-ca.pem" -> "root-ca"
            "/firmware/bry88-esp32-app.bin" -> "firmware"
            "/ota/tenant/VRV/device/deviceLogin" -> "device-login"
            "/jwt/getToken" -> "jwt-token"
            "/gateway/getCaCertificateInfo" -> "ca-info"
            "/ota/tenant/VRV/device/checkUpgrade-json" -> "check-upgrade"
            else -> "unknown"
        }
        try { onDiagnostic("HTTPS endpoint=$endpoint status=${response.status.requestStatus}") } catch (_: Exception) {}
        return response
    }
    private fun handleRequest(s:IHTTPSession):Response = try {
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
                    val offer=firmware!=null && updateReady() && b.optString("deviceType")=="SENSOR3_ESP32" && b.optString("firmwareVersion")!=firmware.version
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
    private fun binary(b:ByteArray):Response {
        val stream=object:java.io.ByteArrayInputStream(b) {
            override fun read(buffer:ByteArray, offset:Int, length:Int):Int = super.read(buffer,offset,minOf(length,2048))
        }
        return newFixedLengthResponse(Response.Status.OK,"application/octet-stream",stream,b.size.toLong()).apply{addHeader("Cache-Control","no-store")}
    }
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
    private val caPem=File(dir,"root-ca.pem")
    private val serverPem=File(dir,"server.pem")
    private val serverP12=File(dir,"identity.p12")
    private val caP12=File(dir,"root-ca.p12")
    private val hostFile=File(dir,"certificate-host.txt")
    private val formatFile=File(dir,"identity-format.txt")
    private val pass=("g3-"+service.packageName+"-private").toCharArray()
    private val formatVersion="2"
    data class Result(val ca:ByteArray,val ssl:SSLContext,val keyStorePath:String,val keyStorePassword:String)

    fun load(host:String):Result {
        if(Security.getProvider("BC")==null)Security.addProvider(BouncyCastleProvider())
        if(!caPem.exists()||!serverPem.exists()||!serverP12.exists()||!caP12.exists()||
            !hostFile.exists()||!formatFile.exists()||formatFile.readText().trim()!=formatVersion) {
            create(host)
        }
        require(hostFile.readText().trim()==host) {
            "手机 IP 已变化；请固定 DHCP 地址，或在重新配网前重新生成本地证书身份"
        }
        val caStore=KeyStore.getInstance("PKCS12")
        caP12.inputStream().use{caStore.load(it,pass)}
        val root=caStore.getCertificate("root") as X509Certificate
        val rootKey=caStore.getKey("root",pass) as PrivateKey
        require(root.basicConstraints>=0) { "本地 Root CA 缺少 CA:TRUE" }
        require(root.keyUsage?.getOrNull(5)==true) { "本地 Root CA 缺少 keyCertSign" }
        root.verify(root.publicKey)

        val ks=KeyStore.getInstance("PKCS12")
        serverP12.inputStream().use{ks.load(it,pass)}
        val leaf=ks.getCertificate("g3-server") as X509Certificate
        val chain=ks.getCertificateChain("g3-server")
        require(chain.size>=2 && chain[1] is X509Certificate) { "服务器证书链不完整" }
        require(leaf.basicConstraints==-1) { "服务器证书必须为 CA:FALSE" }
        require(leaf.issuerX500Principal==root.subjectX500Principal) { "服务器证书签发者与 Root CA 不匹配" }
        leaf.verify(root.publicKey)
        require(leaf.extendedKeyUsage?.contains(KeyPurposeId.id_kp_serverAuth.id)==true) {
            "服务器证书缺少 serverAuth EKU"
        }
        require(leaf.subjectAlternativeNames?.any { it.size>=2 && it[0]==7 && it[1]==host }==true) {
            "服务器证书 SAN 与当前服务 IP 不匹配"
        }
        val km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        km.init(ks,pass)
        val ssl=SSLContext.getInstance("TLS")
        ssl.init(km.keyManagers,null,null)
        return Result(caPem.readBytes(),ssl,serverP12.absolutePath,String(pass))
    }

    private fun create(host:String) {
        val hostIp=java.net.InetAddress.getByName(host).hostAddress
        val now=System.currentTimeMillis()
        val notBefore=Date(now-300000)
        val rootName=X500Name("CN=Daikin G3 Local Migration Root CA")
        val serverName=X500Name("CN=newlifemulti.daikin-china.com.cn")
        val kg=KeyPairGenerator.getInstance("RSA")
        kg.initialize(2048,SecureRandom())
        val rootPair=kg.generateKeyPair()
        val serverPair=kg.generateKeyPair()
        val converter=JcaX509CertificateConverter().setProvider("BC")

        val rootBuilder=JcaX509v3CertificateBuilder(
            rootName,BigInteger(160,SecureRandom()),notBefore,Date(now+3650L*86400000),
            rootName,rootPair.public)
        rootBuilder.addExtension(Extension.basicConstraints,true,BasicConstraints(true))
        rootBuilder.addExtension(Extension.keyUsage,true,KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val rootCert=converter.getCertificate(
            rootBuilder.build(JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootPair.private)))
        rootCert.verify(rootPair.public)

        val leafBuilder=JcaX509v3CertificateBuilder(
            rootName,BigInteger(160,SecureRandom()),notBefore,Date(now+30L*86400000),
            serverName,serverPair.public)
        leafBuilder.addExtension(Extension.basicConstraints,true,BasicConstraints(false))
        leafBuilder.addExtension(Extension.keyUsage,true,KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
        leafBuilder.addExtension(Extension.extendedKeyUsage,false,ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
        leafBuilder.addExtension(Extension.subjectAlternativeName,false,GeneralNames(arrayOf(
            GeneralName(GeneralName.dNSName,"newlifemulti.daikin-china.com.cn"),
            GeneralName(GeneralName.dNSName,"newlifemulti-cdh.daikin-china.com.cn"),
            GeneralName(GeneralName.dNSName,"newlifemulti-cdh-core.daikin-china.com.cn"),
            GeneralName(GeneralName.iPAddress,hostIp))))
        val leafCert=converter.getCertificate(
            leafBuilder.build(JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(rootPair.private)))
        leafCert.verify(rootCert.publicKey)
        require(leafCert.basicConstraints==-1 && leafCert.extendedKeyUsage.contains(KeyPurposeId.id_kp_serverAuth.id)) {
            "生成的服务器证书扩展属性校验失败"
        }

        val caStore=KeyStore.getInstance("PKCS12")
        caStore.load(null,pass)
        caStore.setKeyEntry("root",rootPair.private,pass,arrayOf(rootCert))
        caP12.outputStream().use{caStore.store(it,pass)}

        val serverStore=KeyStore.getInstance("PKCS12")
        serverStore.load(null,pass)
        serverStore.setKeyEntry("g3-server",serverPair.private,pass,arrayOf(leafCert,rootCert))
        serverP12.outputStream().use{serverStore.store(it,pass)}

        fun pem(cert:X509Certificate)= "-----BEGIN CERTIFICATE-----\n"+
            Base64.getMimeEncoder(64,byteArrayOf(10)).encodeToString(cert.encoded)+
            "\n-----END CERTIFICATE-----\n"
        caPem.writeText(pem(rootCert))
        serverPem.writeText(pem(leafCert)+pem(rootCert))
        hostFile.writeText(host)
        formatFile.writeText(formatVersion)
    }
}

/** Keeps the local HTTPS endpoint alive while Android backgrounds the UI. */
class G3MigrationService:Service() {
    private var dns:DnsRedirectServer?=null
    private var server:G3HttpsServer?=null
    private var broker:G3MqttBroker?=null
    private var firmware:G3FirmwareImage?=null
    private var cpuLock:android.os.PowerManager.WakeLock?=null
    private var wifiLock:android.net.wifi.WifiManager.WifiLock?=null
    override fun onBind(i:Intent?):IBinder?=null
    override fun onStartCommand(i:Intent?,flags:Int,startId:Int):Int {
        val channel="g3-local-migration"
        getSystemService(NotificationManager::class.java).createNotificationChannel(NotificationChannel(channel,"G3 迁移服务",NotificationManager.IMPORTANCE_LOW))
        val n=Notification.Builder(this,channel).setSmallIcon(android.R.drawable.stat_sys_upload).setContentTitle("G3 本地 HTTPS 服务").setContentText("DNS ${MigrationPorts.DNS} + HTTPS ${MigrationPorts.HTTPS} + MQTT TLS ${MigrationPorts.MQTT_TLS}").setOngoing(true).build()
        startForeground(41,n)
        if (i?.getBooleanExtra(EXTRA_TRIGGER_OTA,false)==true) {
            val version=i.getStringExtra(EXTRA_VERSION).orEmpty()
            val ok=firmware!=null && firmware?.version==version && broker?.triggerEsp32Upgrade(version)==true
            getSharedPreferences("g3",0).edit().putString("ota_state",if(ok) "ESP32 OTA command sent once" else "OTA blocked: firmware missing, gateway replies incomplete, or device not subscribed").apply()
            if (broker==null) stopSelf()
            return START_NOT_STICKY
        }
        try {
            stopNetworkServices()
            releaseLocks()
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
            require(host.split('.').size == 4 && host.split('.').all { it.matches(Regex("0|[1-9][0-9]{0,2}")) && it.toInt() in 0..255 }) { "虚拟服务地址必须为路由器 IPv4" }
            val id=G3TlsIdentity(this).load(host)
            val firmwarePath=i?.getStringExtra(EXTRA_FIRMWARE_PATH).orEmpty()
            val version=i?.getStringExtra(EXTRA_VERSION).orEmpty()
            firmware=if(firmwarePath.isNotBlank()) G3FirmwareValidator.load(File(firmwarePath),version,i?.getStringExtra(EXTRA_FIRMWARE_SHA256)) else null
            server?.stop();server=G3HttpsServer(MigrationPorts.HTTPS,mac,origin,id.ca,id.ssl,firmware, onDiagnostic = { appendMqttDiagnostic(it) }) { broker?.allGatewayRepliesObserved()==true };server?.start(NanoHTTPD.SOCKET_READ_TIMEOUT,false)
            val gateway=(i?.getStringExtra(EXTRA_GATEWAY)?:"020000000001").replace(":","").replace("-","").uppercase()
            require(Regex("[0-9A-F]{12}").matches(gateway)){"虚拟网关 MAC 无效"}
            broker?.stop();getSharedPreferences("g3",0).edit().putStringSet("gateway_acks", emptySet()).apply();broker=G3MqttBroker(mac,gateway,id.ssl, onAckState = { topics -> getSharedPreferences("g3",0).edit().putStringSet("gateway_acks", HashSet(topics)).apply() }, onDiagnostic = { line -> appendMqttDiagnostic(line) });broker?.start()
            dns=DnsRedirectServer(host,host, onDiagnostic = { appendMqttDiagnostic(it) }).also { it.start() }
            getSharedPreferences("g3",0).edit().putString("service_state","DNS TCP/UDP ${MigrationPorts.DNS} + HTTPS ${MigrationPorts.HTTPS} + MQTT TLS ${MigrationPorts.MQTT_TLS} running").apply()
        } catch(e:Exception) {
            stopNetworkServices()
            releaseLocks()
            getSharedPreferences("g3",0).edit().putString("service_state","ERROR: "+(e.message?:e.javaClass.simpleName)).apply()
            stopSelf()
        }
        return START_NOT_STICKY
    }
    private fun appendMqttDiagnostic(line: String) = MigrationDiagnostics.append(this, line)

    private fun stopNetworkServices() {
        try { dns?.stop() } finally { dns=null }
        try { broker?.stop() } finally { broker=null }
        try { server?.stop() } finally { server=null; firmware=null }
    }
    private fun releaseLocks() {
        try{if(cpuLock?.isHeld==true)cpuLock?.release()}catch(_:Exception){}
        try{if(wifiLock?.isHeld==true)wifiLock?.release()}catch(_:Exception){}
        cpuLock=null;wifiLock=null
    }
    override fun onDestroy(){stopNetworkServices();releaseLocks();super.onDestroy()}
    companion object {
        const val EXTRA_MAC="g3_device_mac"
        const val EXTRA_ORIGIN="g3_origin"
        const val EXTRA_GATEWAY="g3_gateway"
        const val EXTRA_FIRMWARE_PATH="g3_firmware_path"
        const val EXTRA_FIRMWARE_SHA256="g3_firmware_sha256"
        const val EXTRA_VERSION="g3_firmware_version"
        const val EXTRA_TRIGGER_OTA="g3_trigger_ota"
    }
}
