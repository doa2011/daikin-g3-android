package io.github.doa2011.g3provision

import android.Manifest
import android.app.Activity
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.*
import java.util.UUID

class MainActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private val manager by lazy { getSystemService(BLUETOOTH_SERVICE) as BluetoothManager }
    private val devices = linkedMapOf<String, BluetoothDevice>()
    private val deviceLabels = linkedMapOf<String, String>()
    private var scanning = false
    private var scanCount = 0
    private var lastTargetRssiLog = 0L
    private val stopScanRunnable = Runnable { stopScanning() }
    private val service = UUID.fromString("0000ffff-0000-1000-8000-00805f9b34fb")
    private val txUuid = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb")
    private val rxUuid = UUID.fromString("0000ff02-0000-1000-8000-00805f9b34fb")
    private val cccd = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    private var gatt: BluetoothGatt? = null
    private var tx: BluetoothGattCharacteristic? = null
    private var seq = 0
    private var chunks = listOf<ByteArray>()
    private var chunkIndex = 0
    private lateinit var selector: Spinner
    private lateinit var bleAddress: EditText
    private lateinit var ssid: EditText
    private lateinit var password: EditText
    private lateinit var host: EditText
    private lateinit var phoneIp: EditText
    private lateinit var deviceStaMac: EditText
    private lateinit var mac: EditText
    private lateinit var firmwareVersion: EditText
    private var firmwareFile: java.io.File? = null
    private lateinit var output: TextView
    private fun note(s: String) { runOnUiThread { if (::output.isInitialized) output.append(s + "\n") } }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(20,20,20,20) }
        fun field(h: String, initial: String = ""): EditText = EditText(this).apply { hint=h; setText(initial); layout.addView(this) }
        selector = Spinner(this); layout.addView(selector)
        bleAddress = field("BLE MAC（可选；留空时从扫描列表选择）", "")
        ssid = field("2.4GHz Wi-Fi SSID"); password = field("Wi-Fi 密码")
        host = field("虚拟服务 IPv4（建议自动检测的路由器地址）", currentGatewayIpv4()); phoneIp = field("手机 Wi-Fi IPv4（路由器端口转发目标）", currentWifiIpv4()); deviceStaMac = field("G3 Wi-Fi STA MAC（从路由器 DHCP 列表读取）"); mac = field("虚拟网关 MAC", "020000000001"); firmwareVersion = field("目标 ESP32 固件版本（如 1.2.3）")
        layout.addView(Button(this).apply { text="扫描全部 BLE 设备"; setOnClickListener { scan() } })
        layout.addView(Button(this).apply { text="连接扫描选中设备"; setOnClickListener { connect() } })
        layout.addView(Button(this).apply { text="按 MAC 直接连接"; setOnClickListener { connectAddress() } })
        layout.addView(Button(this).apply { text="发送配网（不刷机）"; setOnClickListener { provision() } })
        layout.addView(Button(this).apply { text="启动手机 HTTPS/MQTT 服务"; setOnClickListener { startLocalHttps() } })
        layout.addView(Button(this).apply { text="查看五项网关应答"; setOnClickListener { showGatewayAcks() } })
        layout.addView(Button(this).apply { text="选择 G3 ESP32 raw 固件"; setOnClickListener { chooseFirmware() } })
        layout.addView(Button(this).apply { text="触发 ESP32 OTA（严格检查后单次发送）"; setOnClickListener { triggerOta() } })
        output=TextView(this); layout.addView(ScrollView(this).apply { addView(output) },LinearLayout.LayoutParams(-1,0,1f))
        setContentView(layout); note("配网写入 Wi-Fi 与虚拟服务 IP；STA MAC 从 DHCP 列表读取。手机承载 HTTPS 8443 和 MQTT TLS 8883；固件升级需先验证五项网关应答。")
    }
    private fun permitted(): Boolean {
        val p=if(Build.VERSION.SDK_INT>=31) arrayOf(Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_CONNECT,Manifest.permission.ACCESS_FINE_LOCATION)
            else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        val missing=p.filter { checkSelfPermission(it)!=PackageManager.PERMISSION_GRANTED }
        if(missing.isNotEmpty()) { requestPermissions(missing.toTypedArray(),100); return false }
        return true
    }
    private fun refreshDevices() {
        val selected = selector.selectedItemPosition
        selector.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, deviceLabels.values.toList())
        if (selected >= 0 && selected < deviceLabels.size) selector.setSelection(selected)
    }
    private val scanner=object: ScanCallback() {
        override fun onScanResult(callbackType:Int,result:ScanResult) {
            val address = result.device.address
            val name = result.scanRecord?.deviceName
                ?: try { result.device.name } catch (_: SecurityException) { null }
            val display = name?.takeIf { it.isNotBlank() } ?: "未命名设备"
            scanCount++
            if (address.equals("D0:EF:76:25:5D:CE", true) && android.os.SystemClock.elapsedRealtime() - lastTargetRssiLog > 3000) {
                lastTargetRssiLog = android.os.SystemClock.elapsedRealtime()
                note("已发现目标 G3：$display，RSSI=${result.rssi}")
            }
            if (devices.put(address, result.device) == null) {
                deviceLabels[address] = "$display ($address, RSSI ${result.rssi})"
                runOnUiThread { refreshDevices() }
            }
        }
        override fun onScanFailed(errorCode: Int) {
            scanning = false
            note("扫描失败，错误码=$errorCode")
        }
    }
    private fun stopScanning() {
        if (!scanning) return
        scanning = false
        try { manager.adapter.bluetoothLeScanner?.stopScan(scanner) }
        catch (e: Exception) { note("停止扫描异常: " + e.message) }
        note("扫描结束：收到 $scanCount 条广播，发现 ${devices.size} 台设备")
    }
    private fun scan() {
        if (!permitted()) { note("请先授予附近设备权限，再点击扫描"); return }
        if (!manager.adapter.isEnabled) { note("请先打开蓝牙"); return }
        stopScanning()
        devices.clear()
        deviceLabels.clear()
        refreshDevices()
        scanCount = 0
        val bleScanner = manager.adapter.bluetoothLeScanner ?: return note("BLE 扫描器不可用")
        try {
            scanning = true
            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()
            bleScanner.startScan(null, settings, scanner)
            note("扫描全部 BLE 设备 20 秒；不再按 SENSOR3_ 名称过滤")
            handler.removeCallbacks(stopScanRunnable)
            handler.postDelayed(stopScanRunnable, 20000)
        } catch (e: Exception) {
            scanning = false
            note("启动扫描异常: " + e.message)
        }
    }
    private fun connect() {
        if(!permitted()) return
        val addr=devices.keys.elementAtOrNull(selector.selectedItemPosition) ?: return note("请先扫描")
        note("选中设备: " + (deviceLabels[addr] ?: addr))
        stopScanning()
        connectDevice(devices[addr] ?: return note("选中设备已失效"))
    }
    private fun connectAddress() {
        if (!permitted()) return
        val address = bleAddress.text.toString().trim().uppercase()
        if (!BluetoothAdapter.checkBluetoothAddress(address)) return note("BLE MAC 格式无效")
        try {
            val device = manager.adapter.getRemoteDevice(address)
            connectDevice(device)
        } catch (e: Exception) { note("直接连接失败: " + e.message) }
    }
    private fun connectDevice(device: BluetoothDevice) {
        stopScanning()
        tx = null
        seq = 0
        chunks = emptyList()
        gatt?.close()
        note("尝试 GATT 连接 " + device.address)
        try { gatt = device.connectGatt(this, false, callbacks, BluetoothDevice.TRANSPORT_LE) }
        catch (e: Exception) { note("GATT 异常: " + e.message) }
    }
    private val callbacks=object: BluetoothGattCallback() {
        override fun onConnectionStateChange(g:BluetoothGatt,status:Int,newState:Int) {
            if(status==0&&newState==BluetoothProfile.STATE_CONNECTED) {note("已连接");g.discoverServices()}
            else {note("断开 status="+status);g.close()}
        }
        override fun onServicesDiscovered(g:BluetoothGatt,status:Int) {
            val s=g.getService(service) ?: return note("缺少 FFFF 服务")
            tx=s.getCharacteristic(txUuid)
            val rx=s.getCharacteristic(rxUuid) ?: return note("缺少 FF02")
            if(tx==null) return note("缺少 FF01")
            g.setCharacteristicNotification(rx,true)
            val d=rx.getDescriptor(cccd) ?: return note("缺少 CCCD")
            if(Build.VERSION.SDK_INT>=33) g.writeDescriptor(d,BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
            else { @Suppress("DEPRECATION") d.value=BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                @Suppress("DEPRECATION") g.writeDescriptor(d) }
        }
        override fun onDescriptorWrite(g:BluetoothGatt,d:BluetoothGattDescriptor,status:Int) {
            if(status==0) {note("Notify 已开启");send(0x1c)} else note("Notify 失败")
        }
        override fun onCharacteristicChanged(g:BluetoothGatt,c:BluetoothGattCharacteristic,value:ByteArray) {receive(value)}
        @Suppress("DEPRECATION") override fun onCharacteristicChanged(g:BluetoothGatt,c:BluetoothGattCharacteristic) {receive(c.value?:byteArrayOf())}
    }
    private fun receive(data:ByteArray) {
        note("通知 "+data.joinToString(" ") { "%02X".format(it.toInt() and 255) })
        if(data.isNotEmpty()&&data[0]==0x41.toByte()&&chunks.isNotEmpty()) {note("版本响应收到");sendChunks()}
    }
    private fun send(type:Int,payload:ByteArray=byteArrayOf(),control:Int=0) {
        val c=tx ?: return note("未连接");val g=gatt ?: return
        val frame=byteArrayOf(type.toByte(),control.toByte(),(seq++).toByte(),payload.size.toByte())+payload
        if(Build.VERSION.SDK_INT>=33) g.writeCharacteristic(c,frame,BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
        else { @Suppress("DEPRECATION") c.value=frame
            @Suppress("DEPRECATION") g.writeCharacteristic(c) }
    }


    @Suppress("DEPRECATION")
    private fun currentGatewayIpv4(): String {
        return try {
            val wifi = applicationContext.getSystemService(WIFI_SERVICE) as android.net.wifi.WifiManager
            val gateway = wifi.dhcpInfo.gateway
            if (gateway == 0) "" else listOf(gateway and 255, (gateway shr 8) and 255, (gateway shr 16) and 255, (gateway shr 24) and 255).joinToString(".")
        } catch (_: Exception) { "" }
    }

    @Suppress("DEPRECATION")
    private fun currentWifiIpv4(): String {
        return try {
            val wifi = applicationContext.getSystemService(WIFI_SERVICE) as android.net.wifi.WifiManager
            val ip = wifi.connectionInfo.ipAddress
            if (ip == 0) "" else listOf(ip and 255, (ip shr 8) and 255, (ip shr 16) and 255, (ip shr 24) and 255).joinToString(".")
        } catch (_: Exception) { "" }
    }

    private fun startLocalHttps() {
        try {
            val virtualIp = host.text.toString().trim()
            val virtualParts = virtualIp.split(".")
            val phone = phoneIp.text.toString().trim()
            val phoneParts = phone.split(".")
            require(virtualParts.size == 4 && virtualParts.all { it.toIntOrNull() in 0..255 }) { "虚拟服务 IPv4 无效" }
            require(phoneParts.size == 4 && phoneParts.all { it.toIntOrNull() in 0..255 }) { "手机 Wi-Fi IPv4 无效" }
            require(phone != virtualIp) { "手机 IP 与虚拟服务 IP 应不同；虚拟服务 IP 应填写路由器 LAN 地址" }
            val sta = deviceStaMac.text.toString().trim().replace(":", "").replace("-", "").uppercase()
            require(Regex("[0-9A-F]{12}").matches(sta)) { "请填写 G3 的 Wi-Fi STA MAC，不是 BLE MAC" }
            val gateway = mac.text.toString().trim().replace(":", "").replace("-", "").uppercase()
            require(Regex("[0-9A-F]{12}").matches(gateway)) { "虚拟网关 MAC 无效" }
            val intent = android.content.Intent(this, G3MigrationService::class.java)
                .putExtra(G3MigrationService.EXTRA_MAC, sta)
                .putExtra(G3MigrationService.EXTRA_ORIGIN, "https://" + virtualIp)
                .putExtra(G3MigrationService.EXTRA_GATEWAY, gateway)
                .putExtra(G3MigrationService.EXTRA_FIRMWARE_PATH, firmwareFile?.absolutePath ?: "")
                .putExtra(G3MigrationService.EXTRA_VERSION, firmwareVersion.text.toString().trim())
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
            note("已请求启动手机 HTTPS/MQTT 服务。OpenWrt 将虚拟 IP TCP 443 转发到手机:8443，TCP 8883 转发到手机:8883；OTA 尚未启用。")
        } catch (e: Exception) { note("启动服务参数错误：" + e.message) }
    }


    private fun showGatewayAcks() {
        val acks = getSharedPreferences("g3", 0).getStringSet("gateway_acks", emptySet()) ?: emptySet()
        val expected = listOf("snapshot_upload", "get_weather", "login_ipbox", "get_filter_sensor3", "get_error_sensor3")
        val lines = expected.map { name -> (if (acks.any { it.endsWith(name) }) "✓ " else "○ ") + name }
        note("网关应答进度 " + acks.size + "/5\n" + lines.joinToString("\n"))
    }


    private fun chooseFirmware() {
        val version = firmwareVersion.text.toString().trim()
        if (!version.matches(Regex("[A-Za-z0-9_.-]{1,31}"))) {
            note("请先填写目标固件版本号，再选择固件文件。")
            return
        }
        val intent = android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(android.content.Intent.CATEGORY_OPENABLE)
            .setType("application/octet-stream")
        startActivityForResult(intent, 301)
    }

    private fun triggerOta() {
        val version = firmwareVersion.text.toString().trim()
        if (firmwareFile == null || !firmwareFile!!.exists()) {
            note("尚未选择并验证 G3 ESP32 raw 固件。")
            return
        }
        val intent = android.content.Intent(this, G3MigrationService::class.java)
            .putExtra(G3MigrationService.EXTRA_TRIGGER_OTA, true)
            .putExtra(G3MigrationService.EXTRA_VERSION, version)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
        note("已提交一次 OTA 请求；服务端将检查固件、五项网关应答和设备订阅状态，不满足条件则拒绝发送。")
    }

    @Deprecated("Deprecated in Android")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: android.content.Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != 301 || resultCode != RESULT_OK || data?.data == null) return
        try {
            val dst = java.io.File(filesDir, "selected-g3-esp32.bin")
            contentResolver.openInputStream(data.data!!).use { input ->
                requireNotNull(input) { "无法读取所选固件" }
                dst.outputStream().use { output -> input.copyTo(output) }
            }
            val image = G3FirmwareValidator.load(dst, firmwareVersion.text.toString().trim())
            firmwareFile = dst
            note("G3 ESP32 固件验证通过：大小=" + image.bytes.size + "，版本=" + image.version + "，MD5=" + image.md5)
        } catch (e: Exception) {
            firmwareFile = null
            note("固件拒绝：" + (e.message ?: e.javaClass.simpleName))
        }
    }

    private fun provision() {
        try {
            require(tx!=null) {"未连接"}
            val s=ssid.text.toString().toByteArray();val p=password.text.toString().toByteArray()
            val ip=host.text.toString();val octets=ip.split('.')
            require(octets.size==4&&octets.all {it.toIntOrNull() in 0..255}) {"IPv4 无效"}
            val hex=mac.text.toString().replace(":","")
            require(hex.matches(Regex("[0-9a-fA-F]{12}"))) {"MAC 无效"}
            val m=hex.chunked(2).map {it.toInt(16).toByte()}.toByteArray()
            require((m[0].toInt() and 1)==0&&m.any {it.toInt()!=0}) {"MAC 需为非零单播"}
            require(s.isNotEmpty()&&s.size<=32&&p.size<=64) {"Wi-Fi 长度无效"}
            val addr=ip.toByteArray()
            val body=byteArrayOf(0x42,1,0,0,s.size.toByte())+s+byteArrayOf(p.size.toByte())+p+
                byteArrayOf(addr.size.toByte())+addr+byteArrayOf(6)+m+byteArrayOf(3)
            val list=mutableListOf<ByteArray>();var rest=body
            while(rest.size>16) {list.add(byteArrayOf(rest.size.toByte(),(rest.size shr 8).toByte())+
                rest.take(14).toByteArray());rest=rest.drop(14).toByteArray()}
            list.add(rest);chunks=list;chunkIndex=0
            note("准备发送 "+chunks.size+" 个分片");send(0x1c)
        } catch(e:Exception) {note("错误 "+e.message)}
    }
    private fun sendChunks() {
        if(chunkIndex>=chunks.size) {chunks=emptyList();note("BLE 配网数据已发送；尚不代表设备已入网。请在路由器 DHCP 列表核对 Wi-Fi STA MAC，再检查手机迁移服务日志。");return}
        val i=chunkIndex++;send(0x4d,chunks[i],if(i<chunks.lastIndex)0x10 else 0)
        handler.postDelayed({sendChunks()},600)
    }
    override fun onDestroy() { handler.removeCallbacks(stopScanRunnable); stopScanning(); super.onDestroy();gatt?.close()}
}
