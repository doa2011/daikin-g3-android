package io.github.doa2011.g3provision

import android.Manifest
import android.app.Activity
import android.bluetooth.*
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanSettings
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.location.LocationManager
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
    private var targetSeen = false
    private var targetScanFallbackStarted = false
    private var activeScanSettings: ScanSettings? = null
    private val stopScanRunnable = Runnable { stopScanning() }
    private val targetScanFallbackRunnable = Runnable { startTargetScanFallback() }
    private val blufiTimeoutRunnable = Runnable {
        if (blufiVersionRequested && !blufiVersionReceived) {
            blufiVersionRequested = false
            pendingProvision=false
            note("BLUFi 版本应答超时：5 秒内未收到 0x41。没有发送 Wi-Fi 配置；请确认 G3 处于配网模式后点击“重试 BLUFi 握手”。")
        }
    }
    private var blufiVersionRequested = false
    private var blufiVersionReceived = false
    private var pendingProvision = false
    private var provisioningSending = false
    private var writeInFlight = false
    private var writeRetryCount = 0
    private val writeQueue = java.util.ArrayDeque<ByteArray>()
    private val service = UUID.fromString("0000ffff-0000-1000-8000-00805f9b34fb")
    private val txUuid = UUID.fromString("0000ff01-0000-1000-8000-00805f9b34fb")
    private val rxUuid = UUID.fromString("0000ff02-0000-1000-8000-00805f9b34fb")
    private val cccd = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    private var gatt: BluetoothGatt? = null
    private var tx: BluetoothGattCharacteristic? = null
    private var seq = 0
    private var chunks = emptyList<G3BlufiProtocol.Chunk>()
    private var chunkIndex=0
    private lateinit var selector: Spinner
    private lateinit var bleAddress: EditText
    private lateinit var ssid: EditText
    private lateinit var password: EditText
    private lateinit var host: EditText
    private lateinit var phoneIp: EditText
    private lateinit var deviceStaMac: EditText
    private lateinit var g3Ip: EditText
    private lateinit var sshUser: EditText
    private lateinit var sshPassword: EditText
        private var routerSessionId: String? = null
    private lateinit var mac: EditText
    private lateinit var firmwareVersion: EditText
    private var firmwareFile: java.io.File? = null
    private var firmwareSha256: String? = null
    private lateinit var output: TextView
    private fun note(s: String) { runOnUiThread { if (::output.isInitialized) output.append(s + "\n") } }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
        val layout = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(20,12,20,12) }
        fun field(h: String, initial: String = ""): EditText = EditText(this).apply { hint=h; setText(initial); layout.addView(this) }
        selector = Spinner(this); layout.addView(selector)
        bleAddress = field("BLE MAC（可选，支持直接连接）")
        ssid = field("2.4GHz Wi-Fi SSID"); password = field("Wi-Fi 密码")
        host = field("OpenWrt 路由器 IPv4", currentGatewayIpv4()); phoneIp = field("手机 Wi-Fi IPv4（路由器端口转发目标）", currentWifiIpv4()); deviceStaMac = field("G3 Wi-Fi STA MAC（从路由器 DHCP 获取）"); g3Ip = field("G3 当前 DHCP IPv4（确认后填写）"); sshUser = field("OpenWrt SSH 用户名", "root"); sshPassword = field("OpenWrt SSH 密码").apply { inputType = 129 }; mac = field("虚拟网关 MAC", "020000000001"); firmwareVersion = field("OTA 目标标签（内置 RC7：V99.00.00）", G3FirmwareValidator.BUNDLED_OTA_VERSION)
        layout.addView(Button(this).apply { text="OpenWrt：安装 G3 专用临时转发规则（SSH）"; setOnClickListener { installRouterSession() } })
        layout.addView(Button(this).apply { text="OpenWrt：删除本次临时转发规则"; setOnClickListener { removeRouterSession() } })
        layout.addView(Button(this).apply { text="④ 配网后读取 DHCP 租约并绑定 G3"; setOnClickListener { discoverAndBindG3() } })
        layout.addView(Button(this).apply { text="① 启动手机 HTTPS/MQTT 服务（配网前）"; setOnClickListener { startLocalHttps() } })
        layout.addView(Button(this).apply { text="② 扫描 G3 BLE 设备"; setOnClickListener { scan() } })
        layout.addView(Button(this).apply { text="连接扫描选中设备"; setOnClickListener { connect() } })
        layout.addView(Button(this).apply { text="按 MAC 直接连接"; setOnClickListener { connectAddress() } })
        layout.addView(Button(this).apply { text="重试 BLUFi 握手（读取版本）"; setOnClickListener { requestBlufiVersion(retry=true) } })
        layout.addView(Button(this).apply { text="③ 发送 Wi-Fi 配网（不刷机）"; setOnClickListener { provision() } })
        layout.addView(Button(this).apply { text="查看五项网关应答"; setOnClickListener { showGatewayAcks() } })
        layout.addView(Button(this).apply { text="查看 MQTT 链路诊断（最近100条）"; setOnClickListener { showMqttDiagnostics() } })
        layout.addView(Button(this).apply { text="高级：手动选择其他 G3 raw 固件"; setOnClickListener { chooseFirmware() } })
        layout.addView(Button(this).apply { text="触发 ESP32 OTA（严格检查后单次发送）"; setOnClickListener { triggerOta() } })
        root.addView(ScrollView(this).apply {
            isFillViewport=true
            addView(layout)
        },LinearLayout.LayoutParams(-1,0,1f))
        output=TextView(this).apply { textSize=12f; setPadding(16,8,16,8) }
        root.addView(ScrollView(this).apply { addView(output) },
            LinearLayout.LayoutParams(-1,(180*resources.displayMetrics.density).toInt()))
        setContentView(root)
        note("扫描所有 BLE 广播；BLE MAC、Wi-Fi STA MAC 和虚拟网关 MAC 分别确认。")
        note("完整流程：先启动手机 HTTPS/MQTT，再 BLE 配网；BLUFi 应答后发送配置，入网后由 MQTT 服务应答五项网关请求。")
        try {
            val bundled=G3FirmwareValidator.loadBundled(this)
            firmwareFile=bundled.first
            firmwareSha256=bundled.second.sha256
            firmwareVersion.setText(bundled.second.version)
            note("内置 G3 固件已自动加载：RC7，1,288,544 字节；SHA256 校验通过。OTA 标签 V99.00.00。")
        } catch(e:Exception) {
            note("内置 G3 固件不可用：" + (e.message ?: e.javaClass.simpleName) + "。请重新安装完整 APK。")
        }
    }

    private fun installRouterSession() {
        val router = host.text.toString().trim()
        val user = sshUser.text.toString().trim()
        val secret = sshPassword.text.toString()
        val phone = currentWifiIpv4()
        if (routerSessionId != null) { note("已有活动会话；请先清理或检查路由器状态。"); return }
        if (router.isBlank() || user.isBlank() || secret.isBlank()) { note("安装前只需要填写 OpenWrt 路由器 IP、SSH 用户名和密码。"); return }
        if (phone.isBlank()) { note("无法自动获取手机 Wi-Fi IPv4，请连接 OpenWrt Wi-Fi 后重试。"); return }
        note("正在连接 OpenWrt，预安装本次迁移的禁用规则模板；此时不需要 G3 IP/MAC。")
        Thread {
            try {
                val result = RouterBootstrap.prepare(router,user,secret,phone)
                routerSessionId = result.sessionId
                note("OpenWrt 会话准备成功。四条规则已创建但保持 disabled，不会影响现有设备流量。\n会话 ID：" + result.sessionId + "\n" + result.output + "\nSSH 主机密钥已自动接受并记录，无需手工核验。")
            } catch (e: Exception) { note("OpenWrt 会话准备失败：" + (e.message ?: e.javaClass.simpleName)) }
        }.start()
    }

    private fun removeRouterSession() {
        val id = routerSessionId
        if (id.isNullOrBlank()) { note("本机没有活动会话 ID；为避免误删其他规则，拒绝清理。"); return }
        val router = host.text.toString().trim()
        val user = sshUser.text.toString().trim()
        val secret = sshPassword.text.toString()
        note("正在删除本次会话的临时规则……")
        Thread {
            try {
                val result = RouterBootstrap.cleanup(router,user,secret,id)
                routerSessionId = null
                note("本次 OpenWrt 会话规则已清理。\n" + result.output)
            } catch (e: Exception) { note("清理失败，保留会话 ID 供重试：" + (e.message ?: e.javaClass.simpleName)) }
        }.start()
    }

    private fun discoverAndBindG3() {
        val id = routerSessionId
        if (id.isNullOrBlank()) { note("请先安装 OpenWrt 临时规则模板。"); return }
        val router = host.text.toString().trim()
        val user = sshUser.text.toString().trim()
        val secret = sshPassword.text.toString()
        note("正在读取 OpenWrt DHCP 租约……")
        Thread {
            try {
                val result = RouterBootstrap.readDhcpLeases(router,user,secret)
                val rows = result.output.lineSequence().mapNotNull { line ->
                    val p = line.trim().split(Regex("\\s+"))
                    if (p.size >= 4 && p[1].matches(Regex("(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}")) && p[2].matches(Regex("(?:[0-9]{1,3}\\.){3}[0-9]{1,3}"))) Triple(p[1],p[2],p[3]) else null
                }.toList()
                runOnUiThread {
                    if (rows.isEmpty()) { note("尚未发现 DHCP 租约。请确认 G3 已完成 BLE 配网并连接 Wi-Fi，然后重试。"); return@runOnUiThread }
                    val labels = rows.map { (mac,ip,name) -> "$name  ·  $ip  ·  $mac" }.toTypedArray()
                    android.app.AlertDialog.Builder(this).setTitle("选择刚完成配网的 G3 DHCP 租约")
                        .setItems(labels) { _, which ->
                            val selected = rows[which]
                            deviceStaMac.setText(selected.first)
                            g3Ip.setText(selected.second)
                            Thread {
                                try {
                                    val bound = RouterBootstrap.bind(router,user,secret,id,selected.second)
                                    note("已将 G3 DHCP 身份绑定到本次会话：MAC=" + selected.first + "，IP=" + selected.second + "\n" + bound.output)
                                } catch (e: Exception) { note("绑定 G3 DHCP 地址失败：" + (e.message ?: e.javaClass.simpleName)) }
                            }.start()
                        }.setNegativeButton("取消",null).show()
                }
            } catch (e: Exception) { note("读取 DHCP 租约失败：" + (e.message ?: e.javaClass.simpleName)) }
        }.start()
    }
    private fun requiredBlePermissions(): Array<String> =
        if(Build.VERSION.SDK_INT>=31) arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.ACCESS_FINE_LOCATION
        ) else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)

    private fun permitted(): Boolean {
        val missing=requiredBlePermissions().filter {
            checkSelfPermission(it)!=PackageManager.PERMISSION_GRANTED
        }
        if(missing.isNotEmpty()) {
            note("正在申请 BLE 所需权限：" + missing.joinToString())
            requestPermissions(missing.toTypedArray(),100)
            return false
        }
        if(Build.VERSION.SDK_INT<31) {
            val lm=getSystemService(LOCATION_SERVICE) as LocationManager
            val locationOn=try {
                if(Build.VERSION.SDK_INT>=28) lm.isLocationEnabled
                else @Suppress("DEPRECATION") (lm.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER))
            } catch(_:Exception) { false }
            if(!locationOn) {
                note("Android 6–11 扫描 BLE 需要开启系统定位服务；请打开定位后重新扫描。")
                return false
            }
        }
        return true
    }

    @Suppress("DEPRECATION")
    override fun onRequestPermissionsResult(
        requestCode:Int, permissions:Array<out String>, grantResults:IntArray
    ) {
        super.onRequestPermissionsResult(requestCode,permissions,grantResults)
        if(requestCode==100) {
            val denied=permissions.indices.filter { grantResults.getOrNull(it)!=PackageManager.PERMISSION_GRANTED }
                .map { permissions[it] }
            if(grantResults.isNotEmpty() && denied.isEmpty()) {
                note("BLE 权限已授予，自动开始扫描。")
                handler.post { scan() }
            } else {
                note("BLE 权限未授予：" + denied.joinToString() + "。请在系统设置中允许附近设备权限。")
            }
        }
    }
    private fun refreshDevices() {
        val selected = selector.selectedItemPosition
        selector.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, deviceLabels.values.toList())
        if (selected >= 0 && selected < deviceLabels.size) selector.setSelection(selected)
    }
    private fun recordScanResult(result:ScanResult) {
        val address=try { result.device.address } catch(e:SecurityException) {
            note("读取 BLE 地址失败：缺少 BLUETOOTH_SCAN 权限")
            return
        }
        val name=result.scanRecord?.deviceName?.takeIf { it.isNotBlank() }
            ?: try { result.device.name } catch(_:SecurityException) { null }
        val display=name?.takeIf { it.isNotBlank() } ?: "未命名设备"
        scanCount++
        val isTarget = address.equals(bleAddress.text.toString().trim(),true) || display.startsWith("SENSOR3_",true)
        if(isTarget) {
            targetSeen=true
            handler.removeCallbacks(targetScanFallbackRunnable)
            if(android.os.SystemClock.elapsedRealtime()-lastTargetRssiLog>1500) {
                lastTargetRssiLog=android.os.SystemClock.elapsedRealtime()
                note("发现 G3 广播：$display，BLE=$address，RSSI=\${result.rssi}")
            }
        }
        val newDevice=devices.put(address,result.device)==null
        val nameImproved=display!="未命名设备" && deviceLabels[address]?.startsWith("未命名设备 (")==true
        if(newDevice || nameImproved) {
            deviceLabels[address]="$display ($address, RSSI \${result.rssi})"
            runOnUiThread { refreshDevices() }
            if(scanCount==1) note("已收到 BLE 广播，正在列出设备。")
        }
    }

    private val scanner=object: ScanCallback() {
        override fun onScanResult(callbackType:Int,result:ScanResult) = recordScanResult(result)
        override fun onBatchScanResults(results:MutableList<ScanResult>) {
            results.forEach { recordScanResult(it) }
        }
        override fun onScanFailed(errorCode:Int) {
            scanning=false
            handler.removeCallbacks(stopScanRunnable)
            handler.removeCallbacks(targetScanFallbackRunnable)
            val reason=when(errorCode) {
                SCAN_FAILED_ALREADY_STARTED -> "扫描已启动"
                SCAN_FAILED_APPLICATION_REGISTRATION_FAILED -> "系统 BLE 扫描注册失败"
                SCAN_FAILED_INTERNAL_ERROR -> "Android 蓝牙栈内部错误"
                SCAN_FAILED_FEATURE_UNSUPPORTED -> "设备不支持该扫描功能"
                else -> "未知扫描错误"
            }
            note("BLE 扫描失败：$reason（错误码=$errorCode）。请检查蓝牙开关、权限及系统蓝牙服务。")
        }
    }
    private fun stopScanning() {
        if (!scanning) return
        scanning = false
        handler.removeCallbacks(targetScanFallbackRunnable)
        try { manager.adapter.bluetoothLeScanner?.stopScan(scanner) }
        catch (e: Exception) { note("停止扫描异常: " + e.message) }
        note("扫描结束：收到 $scanCount 条广播，发现 \${devices.size} 台设备")
        if(!targetSeen) {
            if(scanCount==0) note("本轮没有收到任何 BLE 广播。请确认蓝牙/定位授权、系统定位开关及 G3 已短按后盖网络键进入配网状态。")
            else note("收到了 BLE 广播；未识别 SENSOR3 名称。仍可选择无名称设备或输入 MAC 直接连接。")
        }
    }
    private fun scan() {
        if(scanning) {
            note("BLE 扫描已经进行中。")
            return
        }
        if(!permitted()) return
        val adapter=try { manager.adapter } catch(e:Exception) {
            note("无法取得 Android BluetoothAdapter：" + e.message)
            return
        }
        if(adapter==null) return note("此手机没有 BluetoothAdapter")
        if(!adapter.isEnabled) return note("手机蓝牙未开启，请先打开蓝牙后重新扫描")
        val bleScanner=adapter.bluetoothLeScanner ?: return note("系统 BLE Scanner 不可用；请确认手机支持 BLE 且蓝牙已开启")
        devices.clear()
        deviceLabels.clear()
        refreshDevices()
        scanCount=0
        lastTargetRssiLog=0L
        targetSeen=false
        targetScanFallbackStarted=false
        try {
            val settings=ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
                .setMatchMode(ScanSettings.MATCH_MODE_AGGRESSIVE)
                .setNumOfMatches(ScanSettings.MATCH_NUM_MAX_ADVERTISEMENT)
                .setReportDelay(0L)
                .build()
            activeScanSettings=settings
            // First pass deliberately scans all advertisements; a target-MAC pass follows if needed.
            scanning=true
            bleScanner.startScan(null,settings,scanner)
            note("BLE 全设备扫描已启动，持续 30 秒；无名称设备也会显示。")
            handler.removeCallbacks(stopScanRunnable)
            handler.removeCallbacks(targetScanFallbackRunnable)
            handler.postDelayed(targetScanFallbackRunnable,10000)
            handler.postDelayed(stopScanRunnable,30000)
        } catch(e:SecurityException) {
            scanning=false
            note("系统拒绝 BLE 扫描：" + e.message + "。请检查附近设备权限。")
        } catch(e:IllegalStateException) {
            scanning=false
            note("蓝牙服务当前不可用：" + e.message)
        } catch(e:Exception) {
            scanning=false
            note("启动 BLE 扫描异常：" + e.javaClass.simpleName + ": " + e.message)
        }
    }
    private fun startTargetScanFallback() {
        if(!scanning || targetSeen || targetScanFallbackStarted) return
        if(!BluetoothAdapter.checkBluetoothAddress(bleAddress.text.toString().trim().uppercase())) return
        val bleScanner=try { manager.adapter.bluetoothLeScanner } catch(_:Exception) { null } ?: return
        try {
            bleScanner.stopScan(scanner)
            val address=bleAddress.text.toString().trim().uppercase()
            val filter=ScanFilter.Builder().setDeviceAddress(address).build()
            bleScanner.startScan(listOf(filter),activeScanSettings,scanner)
            targetScanFallbackStarted=true
            note("前 10 秒未发现 G3，已切换为用户指定 BLE MAC 精确扫描：$address。")
        } catch(e:Exception) {
            note("G3 目标 MAC 二次扫描启动失败：" + e.javaClass.simpleName + ": " + e.message)
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
        chunkIndex=0
        pendingProvision=false
        provisioningSending=false
        writeInFlight=false
        blufiVersionRequested=false
        blufiVersionReceived=false
        handler.removeCallbacks(blufiTimeoutRunnable)
        gatt?.close()
        note("尝试 GATT 连接 " + device.address)
        try { gatt = device.connectGatt(this, false, callbacks, BluetoothDevice.TRANSPORT_LE) }
        catch (e: Exception) { note("GATT 异常: " + e.message) }
    }
    private val callbacks=object: BluetoothGattCallback() {
        override fun onConnectionStateChange(g:BluetoothGatt,status:Int,newState:Int) {
            if(status==0&&newState==BluetoothProfile.STATE_CONNECTED) {note("已连接");g.discoverServices()}
            else { handler.post { if(g===gatt) { note("BLE 断开 status=$status，已提交分片 $chunkIndex/${chunks.size}"); gatt=null; tx=null; provisioningSending=false; pendingProvision=false; writeInFlight=false; blufiVersionRequested=false; handler.removeCallbacks(blufiTimeoutRunnable); chunks=emptyList() }; g.close() } }
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
            if(status==0) {handler.post { if(g===gatt) {note("Notify 已开启");requestBlufiVersion()} }} else note("Notify 失败")
        }
        override fun onCharacteristicWrite(g:BluetoothGatt,c:BluetoothGattCharacteristic,status:Int) {
            handler.post {
                if(g!==gatt) return@post
                writeInFlight=false
                if(status!=0) {
                    provisioningSending=false; pendingProvision=false; blufiVersionRequested=false
                    handler.removeCallbacks(blufiTimeoutRunnable)
                    note("BLE 写入失败 status=$status；停止发送，请重新连接")
                } else if(provisioningSending) {
                    val sent = chunkIndex
                    note("BLE 写入成功：分片 $sent/${chunks.size}")
                    if(sent == 0) sendChunks()
                    else if(sent < chunks.size) handler.postDelayed({
                        if(g===gatt && provisioningSending && chunkIndex==sent) sendChunks()
                    },500)
                    else {
                        note("末片写入成功，等待2秒")
                        handler.postDelayed({
                            if(g===gatt && provisioningSending && chunkIndex==sent) {
                                sendChunks()
                                note("主动断开 BLE")
                                g.disconnect()
                            }
                        },2000)
                    }
                }
            }
        }
        override fun onCharacteristicChanged(g:BluetoothGatt,c:BluetoothGattCharacteristic,value:ByteArray) {if(g===gatt) receive(g,value)}
        @Suppress("DEPRECATION") override fun onCharacteristicChanged(g:BluetoothGatt,c:BluetoothGattCharacteristic) {if(g===gatt) receive(g,c.value?.copyOf()?:byteArrayOf())}
    }
    private fun receive(g:BluetoothGatt,data:ByteArray) {
        note("BLE 通知：类型=${data.firstOrNull()?.toInt()?.and(255)} 长度=${data.size}")
        val version=G3BlufiProtocol.parseVersionNotification(data) ?: return
        handler.post {
            if (g!==gatt || !blufiVersionRequested) return@post
            handler.removeCallbacks(blufiTimeoutRunnable)
            blufiVersionRequested=false
            blufiVersionReceived=true
            note("BLUFi 版本响应：${version.major}.${version.minor}")
            if(pendingProvision) {
                pendingProvision=false
                provisioningSending=true
                if(!writeInFlight) sendChunks()
            }
        }
    }
    private fun requestBlufiVersion(retry:Boolean=false) {
        if(tx==null || gatt==null) return note("未连接")
        if(provisioningSending || writeInFlight) return note("BLE 写入进行中")
        if(blufiVersionRequested && !retry) return
        blufiVersionRequested=true
        blufiVersionReceived=false
        handler.removeCallbacks(blufiTimeoutRunnable)
        if(send(0x1c)) handler.postDelayed(blufiTimeoutRunnable,5000)
        else blufiVersionRequested=false
    }
    private fun send(type:Int,payload:ByteArray=byteArrayOf(),control:Int=0):Boolean {
        val c=tx ?: return false
        val g=gatt ?: return false
        if(writeInFlight) return false
        val frame=G3BlufiProtocol.frame(type,control,seq and 255,payload)
        val accepted=try {
            if(Build.VERSION.SDK_INT>=33) g.writeCharacteristic(c,frame,BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)==0
            else { @Suppress("DEPRECATION") c.value=frame
                @Suppress("DEPRECATION") g.writeCharacteristic(c) }
        } catch(e:Exception) { note("BLE 写入异常："+e.message); false }
        if(accepted) { seq=(seq+1) and 255; writeInFlight=true }
        else note("BLE 写入未被接受")
        return accepted
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
            if(firmwareFile==null) {
                val bundled=G3FirmwareValidator.loadBundled(this)
                firmwareFile=bundled.first
                firmwareSha256=bundled.second.sha256
                firmwareVersion.setText(bundled.second.version)
            }
            val selected=firmwareFile ?: error("没有可用的 G3 ESP32 固件")
            val version=firmwareVersion.text.toString().trim()
            val image=G3FirmwareValidator.load(selected,version,firmwareSha256)
            val intent = android.content.Intent(this, G3MigrationService::class.java)
                .putExtra(G3MigrationService.EXTRA_MAC, sta)
                .putExtra(G3MigrationService.EXTRA_ORIGIN, "https://" + virtualIp)
                .putExtra(G3MigrationService.EXTRA_GATEWAY, gateway)
                .putExtra(G3MigrationService.EXTRA_FIRMWARE_PATH, selected.absolutePath)
                .putExtra(G3MigrationService.EXTRA_FIRMWARE_SHA256, image.sha256)
                .putExtra(G3MigrationService.EXTRA_VERSION, image.version)
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
            note("已请求启动手机 HTTPS/MQTT 服务。OpenWrt 将虚拟 IP TCP ${MigrationPorts.FACTORY_HTTPS} 转发到手机:${MigrationPorts.HTTPS}，TCP ${MigrationPorts.FACTORY_MQTT_TLS} 转发到手机:${MigrationPorts.MQTT_TLS}。只有五项网关应答完成后才能手动触发 OTA。")
        } catch (e: Exception) { note("启动服务参数错误：" + e.message) }
    }


    private fun showMqttDiagnostics() {
        val log=getSharedPreferences("g3",0).getString("mqtt_diag","").orEmpty()
        note(if(log.isBlank()) "尚无 MQTT 诊断事件。请先启动手机服务，再让 G3 配网并连接网关。" else "MQTT 链路诊断（最近100条）\\n"+log)
    }

    private fun showGatewayAcks() {
        val acks = getSharedPreferences("g3", 0).getStringSet("gateway_acks", emptySet()) ?: emptySet()
        val expected = listOf("snapshot_upload", "get_weather", "login_ipbox", "get_filter_sensor3", "get_error_sensor3")
        val lines = expected.map { name -> (if (acks.any { it.endsWith(name) }) "✓ " else "○ ") + name }
        val ota = getSharedPreferences("g3", 0).getString("ota_state", "尚未触发") ?: "尚未触发"
        note("网关应答进度 " + acks.size + "/5\n" + lines.joinToString("\n") + "\nOTA 状态：" + ota)
    }


    private fun chooseFirmware() {
        val version = firmwareVersion.text.toString().trim()
        if (!version.matches(Regex("[A-Za-z0-9_.-]{1,31}"))) {
            note("请先填写目标固件版本号，再选择固件文件。")
            return
        }
        val intent = android.content.Intent(android.content.Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(android.content.Intent.CATEGORY_OPENABLE)
            .setType("*/*")
        startActivityForResult(intent, 301)
    }

    private fun triggerOta() {
        val version = firmwareVersion.text.toString().trim()
        try {
            if (firmwareFile == null || !firmwareFile!!.exists()) {
                val bundled=G3FirmwareValidator.loadBundled(this)
                firmwareFile=bundled.first
                firmwareSha256=bundled.second.sha256
                firmwareVersion.setText(bundled.second.version)
            }
            val selected=firmwareFile ?: error("没有可用固件")
            val image=G3FirmwareValidator.load(selected,version,firmwareSha256)
            firmwareSha256=image.sha256
        } catch(e:Exception) {
            note("OTA 已阻止，固件校验失败：" + (e.message ?: e.javaClass.simpleName))
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
            firmwareSha256 = image.sha256
            note("手动固件验证通过：大小=" + image.bytes.size + "，版本=" + image.version + "，SHA256=" + image.sha256 + "，MD5=" + image.md5)
        } catch (e: Exception) {
            firmwareFile = null
            firmwareSha256 = null
            note("固件拒绝：" + (e.message ?: e.javaClass.simpleName))
        }
    }

    private fun provision() {
        try {
            require(tx!=null && gatt!=null) {"未连接"}
            require(!provisioningSending && !pendingProvision && !writeInFlight) {"BLE 写入进行中"}
            val body=G3BlufiProtocol.buildWifiConfig(ssid.text.toString(),password.text.toString(),host.text.toString().trim(),mac.text.toString())
            chunks=G3BlufiProtocol.fragment(body)
            chunkIndex=0
            note("准备发送 "+chunks.size+" 个分片")
            pendingProvision=true
            requestBlufiVersion(retry=true)
            if(!blufiVersionRequested) pendingProvision=false
        } catch(e:Exception) {note("错误 "+e.message)}
    }
    private fun sendChunks() {
        if(!provisioningSending || writeInFlight) return
        if(chunkIndex>=chunks.size) {
            chunks=emptyList()
            provisioningSending=false
            note("BLE 配网分片写入完成；尚不代表设备已入网。请核对 DHCP 与迁移服务日志。")
            return
        }
        val chunk=chunks[chunkIndex]
        if(send(0x4d,chunk.payload,chunk.control)) { note("BLE 分片 ${chunkIndex+1}/${chunks.size} seq=${(seq+255) and 255} control=${chunk.control} len=${chunk.payload.size}"); chunkIndex++ }
        else provisioningSending=false
    }
    override fun onDestroy() { handler.removeCallbacks(stopScanRunnable); stopScanning(); super.onDestroy();gatt?.close()}
}
