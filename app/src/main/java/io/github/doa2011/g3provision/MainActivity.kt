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
    private lateinit var networkLog: TextView
    private lateinit var accessLog: TextView
    private lateinit var migrationLog: TextView
    private lateinit var connectionStatus: TextView
    private lateinit var routerStatus: TextView
    private lateinit var gatewayAckPanel: LinearLayout
    private fun note(s: String) { runOnUiThread {
        val stamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault()).format(java.util.Date())
        val line = "[$stamp] $s"
        fun appendBounded(view: TextView) {
            val lines = (view.text.toString().lineSequence() + sequenceOf(line)).toList().takeLast(160)
            view.text = lines.joinToString("\n")
        }
        if (::output.isInitialized) appendBounded(output)
        if (::networkLog.isInitialized) appendBounded(networkLog)
        if (::accessLog.isInitialized) appendBounded(accessLog)
        if (::migrationLog.isInitialized) appendBounded(migrationLog)
    } }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
        val pages = linkedMapOf<String, ScrollView>()
        val content = android.widget.FrameLayout(this)
        fun createPage(key: String, title: String, subtitle: String): LinearLayout {
            val page = LinearLayout(this).apply {
                orientation=LinearLayout.VERTICAL
                setPadding(20,12,20,12)
                addView(TextView(this@MainActivity).apply {
                    text=title; textSize=22f
                    setTypeface(typeface, android.graphics.Typeface.BOLD)
                })
                addView(TextView(this@MainActivity).apply { text=subtitle; setPadding(0,8,0,16) })
            }
            val scroll=ScrollView(this).apply { isFillViewport=true; addView(page) }
            pages[key]=scroll
            content.addView(scroll,android.widget.FrameLayout.LayoutParams(-1,-1))
            return page
        }
        fun field(page: LinearLayout, hintText: String, initial: String = ""): EditText =
            EditText(this).apply { hint=hintText; setText(initial); page.addView(this) }
        fun action(page: LinearLayout, label: String, onClick: () -> Unit) {
            page.addView(Button(this).apply { text=label; setOnClickListener { onClick() } })
        }
        host=EditText(this).apply { hint="OpenWrt 路由器地址"; setText(currentGatewayIpv4()) }
        sshUser=EditText(this).apply { hint="路由器用户名"; setText("root") }
        sshPassword=EditText(this).apply { hint="路由器密码"; inputType=129 }
        phoneIp=EditText(this).apply { setText(currentWifiIpv4()) }
        ssid=EditText(this)
        password=EditText(this).apply { inputType=129 }
        bleAddress=EditText(this)
        deviceStaMac=EditText(this)
        g3Ip=EditText(this)
        mac=EditText(this).apply { setText("020000000001") }
        firmwareVersion=EditText(this).apply { setText(G3FirmwareValidator.BUNDLED_OTA_VERSION) }
        selector=Spinner(this)
        run {
            val page=createPage("network","配网","填写路由器与 G3 无线接入点信息；保存后准备本次设备专用转发。")
            page.addView(TextView(this).apply { text="路由器"; textSize=17f; setTypeface(typeface,android.graphics.Typeface.BOLD) })
            page.addView(host); page.addView(sshUser); page.addView(sshPassword)
            page.addView(TextView(this).apply { text="接入点信息"; textSize=17f; setPadding(0,18,0,4); setTypeface(typeface,android.graphics.Typeface.BOLD) })
            field(page,"接入点 SSID").also { ssid=it }
            field(page,"接入点密码").also { password=it; it.inputType=129 }
            routerStatus=TextView(this).apply {
                text="● 路由器转发尚未开启"
                setTextColor(0xffb26a00.toInt()); setPadding(0,16,0,8)
            }
            page.addView(routerStatus)
            networkLog=TextView(this).apply { textSize=11f; setPadding(4,8,4,8); text=\"配网操作状态\\n\" }
            page.addView(networkLog)
            action(page,"保存并准备路由器转发") {
                phoneIp.setText(currentWifiIpv4())
                installRouterSession()
            }
            action(page,"清理本次路由器转发") { removeRouterSession() }
        }
        run {
            val page=createPage("access","接入","连接 G3 后发送接入点参数；不要求先完成其他标签操作。")
            connectionStatus=TextView(this).apply {
                text="● 尚未连接 G3"
                setTextColor(0xffb3261e.toInt())
                setPadding(12,12,12,12)
                setBackgroundColor(0xffffebee.toInt())
            }
            page.addView(connectionStatus)
            accessLog=TextView(this).apply { textSize=11f; setPadding(4,8,4,8); text=\"接入操作状态\\n\" }
            page.addView(accessLog)
            page.addView(selector)
            action(page,"扫描并连接 G3") { scan() }
            action(page,"发送配网参数") { provision() }
            action(page,"高级") { showAccessAdvanced() }
        }
        run {
            val page=createPage("migration","迁移","发送 ESP32 / MCU 固件，并观察网关应答状态。")
            action(page,"发送 OTA（ESP32 固件）") { triggerOta() }
            action(page,"发送 MCU 固件") { showMcuUpgradeStatus() }
            action(page,"高级") { showMigrationAdvanced() }
            page.addView(TextView(this).apply {
                text="五项网关应答检测"; textSize=18f
                setTypeface(typeface,android.graphics.Typeface.BOLD)
                setPadding(0,20,0,8)
            })
            gatewayAckPanel=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL }
            page.addView(gatewayAckPanel)
            migrationLog=TextView(this).apply { textSize=11f; setPadding(4,8,4,8); text=\"迁移操作状态\\n\" }
            page.addView(migrationLog)
        }
        run {
            val page=createPage("diagnostics","诊断","总体操作日志与 MQTT 链路诊断。")
            action(page,"打开 MQTT 链路诊断") { showMqttDiagnostics() }
            output=TextView(this).apply { textSize=12f; setPadding(4,12,4,12) }
            page.addView(output)
        }
        val navigation=LinearLayout(this).apply {
            orientation=LinearLayout.HORIZONTAL
            setPadding(4,4,4,4)
            setBackgroundColor(0xfff1f4f8.toInt())
        }
        val navButtons=linkedMapOf<String,Button>()
        fun selectPage(key:String) {
            pages.forEach { (id,view) -> view.visibility=if(id==key) android.view.View.VISIBLE else android.view.View.GONE }
            navButtons.forEach { (id,button) ->
                button.isEnabled=id!=key
                button.alpha=if(id==key) 1f else 0.72f
            }
        }
        listOf("network" to "配网","access" to "接入","migration" to "迁移","diagnostics" to "诊断").forEach { (key,label) ->
            val button=Button(this).apply {
                text=label; textSize=14f; minWidth=0
                setPadding(2,8,2,8)
                setOnClickListener { selectPage(key) }
            }
            navButtons[key]=button
            navigation.addView(button,LinearLayout.LayoutParams(0,-2,1f))
        }
        selectPage("network")
        root.addView(content,LinearLayout.LayoutParams(-1,0,1f))
        root.addView(navigation,LinearLayout.LayoutParams(-1,-2))
        setContentView(root)
        renderGatewayAcks()
        note("四个标签可独立操作；缺少前置条件时会提示，但不会锁住其他标签。")
        note("BLE MAC、Wi-Fi STA MAC 与虚拟网关 MAC 是不同身份，不能互相推算。")
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
        note("配网：正在连接 OpenWrt，准备本次迁移的路由器转发规则；手机地址=$phone。")
        runOnUiThread { routerStatus.text=\"● 正在连接路由器并配置转发…\"; routerStatus.setTextColor(0xffb26a00.toInt()) }
        Thread {
            try {
                MigrationDiagnostics.append(this, "SSH operation=prepare START")
                val result = RouterBootstrap.prepare(router,user,secret,phone)
                MigrationDiagnostics.append(this, "SSH operation=prepare OK")
                routerSessionId = result.sessionId
                runOnUiThread { routerStatus.text="● 路由器规则已准备；请继续接入 G3"; routerStatus.setTextColor(0xff137333.toInt()) }
                note("OpenWrt 会话准备成功。四条 G3 专用规则已创建但保持 disabled；识别并绑定 G3 DHCP 身份后才会启用，不影响其他设备。\n会话 ID：" + result.sessionId + "\n" + result.output + "\nSSH 主机密钥采用首次信任，未进行独立核验。")
            } catch (e: Exception) {
                MigrationDiagnostics.append(this, "SSH operation=prepare ERROR type=${e.javaClass.simpleName}")
                runOnUiThread { routerStatus.text=\"● 转发配置失败\"; routerStatus.setTextColor(0xffb3261e.toInt()) }
                note("配网：OpenWrt 转发配置失败：" + (e.message ?: e.javaClass.simpleName))
            }
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
                MigrationDiagnostics.append(this, "SSH operation=cleanup START")
                val result = RouterBootstrap.cleanup(router,user,secret,id)
                MigrationDiagnostics.append(this, "SSH operation=cleanup OK")
                routerSessionId = null
                note("本次 OpenWrt 会话规则已清理。\n" + result.output)
            } catch (e: Exception) { MigrationDiagnostics.append(this, "SSH operation=cleanup ERROR type=${e.javaClass.simpleName}"); note("清理失败，保留会话 ID 供重试：" + (e.message ?: e.javaClass.simpleName)) }
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
                MigrationDiagnostics.append(this, "SSH operation=leases START")
                val result = RouterBootstrap.readDhcpLeases(router,user,secret)
                MigrationDiagnostics.append(this, "SSH operation=leases OK")
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
                                    MigrationDiagnostics.append(this, "SSH operation=bind START")
                val bound = RouterBootstrap.bind(router,user,secret,id,selected.second)
                MigrationDiagnostics.append(this, "SSH operation=bind OK")
                                    runOnUiThread { routerStatus.text="● G3 专用路由器转发已开启"; routerStatus.setTextColor(0xff137333.toInt()); routerStatus.setBackgroundColor(0xffe6f4ea.toInt()) }
                                    note("已将 G3 DHCP 身份绑定到本次会话：MAC=" + selected.first + "，IP=" + selected.second + "\n" + bound.output)
                                } catch (e: Exception) { MigrationDiagnostics.append(this, "SSH operation=bind ERROR type=${e.javaClass.simpleName}"); note("绑定 G3 DHCP 地址失败：" + (e.message ?: e.javaClass.simpleName)) }
                            }.start()
                        }.setNegativeButton("取消",null).show()
                }
            } catch (e: Exception) { MigrationDiagnostics.append(this, "SSH operation=leases ERROR type=${e.javaClass.simpleName}"); note("读取 DHCP 租约失败：" + (e.message ?: e.javaClass.simpleName)) }
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
        connectionStatus.text="● 正在连接 G3…"; connectionStatus.setTextColor(0xffb26a00.toInt()); connectionStatus.setBackgroundColor(0xfffff4e5.toInt())
        note("尝试 GATT 连接 " + device.address)
        try { gatt = device.connectGatt(this, false, callbacks, BluetoothDevice.TRANSPORT_LE) }
        catch (e: Exception) { note("GATT 异常: " + e.message) }
    }
    private val callbacks=object: BluetoothGattCallback() {
        override fun onConnectionStateChange(g:BluetoothGatt,status:Int,newState:Int) {
            if(status==0&&newState==BluetoothProfile.STATE_CONNECTED) { handler.post { if(g===gatt) { connectionStatus.text="● G3 已连接"; connectionStatus.setTextColor(0xff137333.toInt()); connectionStatus.setBackgroundColor(0xffe6f4ea.toInt()); note("已连接"); g.discoverServices() } } }
            else { handler.post { if(g===gatt) { connectionStatus.text="● G3 未连接"; connectionStatus.setTextColor(0xffb3261e.toInt()); connectionStatus.setBackgroundColor(0xffffebee.toInt()); note("BLE 断开 status=$status，已提交分片 $chunkIndex/${chunks.size}"); gatt=null; tx=null; provisioningSending=false; pendingProvision=false; writeInFlight=false; blufiVersionRequested=false; handler.removeCallbacks(blufiTimeoutRunnable); chunks=emptyList() }; g.close() } }
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


    private var mqttDialog: android.app.AlertDialog? = null
    private var mqttExportSnapshot: String? = null

    private fun showMqttDiagnostics() {
        mqttDialog?.dismiss()
        val prefs = getSharedPreferences("g3", 0)
        val panel = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(16, 8, 16, 8)
        }
        val categories = listOf("全部", "TCP/TLS", "CONNECT", "SUBSCRIBE", "PUBLISH/RX/TX", "异常/拒绝", "DNS", "HTTPS", "SSH")
        val category = Spinner(this).apply {
            adapter = ArrayAdapter(this@MainActivity, android.R.layout.simple_spinner_dropdown_item, categories)
        }
        val search = EditText(this).apply { hint = "搜索主题或日志"; isSingleLine = true }
        val pause = CheckBox(this).apply { text = "暂停显示（后台仍记录）" }
        val summary = TextView(this)
        val log = TextView(this).apply { setTextIsSelectable(true); textSize = 12f }
        val scroll = ScrollView(this).apply { addView(log) }
        panel.addView(category)
        panel.addView(search)
        panel.addView(pause)
        panel.addView(summary)
        val actions = LinearLayout(this)
        panel.addView(actions)
        panel.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))
        var snapshot = ""
        fun readSnapshot(): String = prefs.getString("mqtt_diag", "").orEmpty()
            .lineSequence().filter { it.isNotBlank() }.toList().takeLast(100)
            .joinToString("\n").takeLast(65536)
        fun render() {
            if (!pause.isChecked) snapshot = readSnapshot()
            val query = search.text.toString().trim()
            val terms = when (category.selectedItemPosition) {
                1 -> listOf("TCP", "TLS")
                2 -> listOf("CONNECT")
                3 -> listOf("SUBSCRIBE")
                4 -> listOf("PUBLISH", " RX", " TX")
                5 -> listOf("fail", "error", "reject", "exception", "失败", "拒绝")
                6 -> listOf("DNS ")
                7 -> listOf("HTTPS ")
                8 -> listOf("SSH ")
                else -> emptyList()
            }
            val lines = snapshot.lineSequence().filter { it.isNotBlank() }.filter { line ->
                (terms.isEmpty() || terms.any { line.contains(it, ignoreCase = true) }) &&
                    line.contains(query, ignoreCase = true)
            }.toList()
            val visible = lines.joinToString("\n")
            if (log.text.toString() != visible) log.text = visible
            summary.text = "显示 ${lines.size} 条；" + if (pause.isChecked) "已暂停" else "每秒刷新"
        }
        fun action(label: String, block: () -> Unit) {
            actions.addView(Button(this).apply {
                text = label
                setOnClickListener { block() }
            }, LinearLayout.LayoutParams(0, -2, 1f))
        }
        action("复制") {
            val clipboard = getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager
            clipboard.setPrimaryClip(android.content.ClipData.newPlainText("MQTT", log.text))
        }
        action("导出") {
            mqttExportSnapshot = log.text.toString()
            val intent = android.content.Intent(android.content.Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(android.content.Intent.CATEGORY_OPENABLE)
                .setType("text/plain")
                .putExtra(android.content.Intent.EXTRA_TITLE, "g3-network-diagnostics.txt")
            startActivityForResult(intent, 302)
        }
        action("清空") {
            android.app.AlertDialog.Builder(this).setMessage("清空历史网络诊断日志？不会重置网关应答状态。")
                .setNegativeButton("取消", null)
                .setPositiveButton("清空") { _, _ ->
                    MigrationDiagnostics.clear(this@MainActivity)
                    snapshot = ""
                    render()
                }.show()
        }
        val dialog = android.app.AlertDialog.Builder(this)
            .setTitle("网络与 MQTT 实时诊断")
            .setView(panel).setPositiveButton("关闭", null).create()
        val refresh = object : Runnable {
            override fun run() {
                if (!dialog.isShowing || isFinishing || isDestroyed) return
                render()
                handler.postDelayed(this, 1000L)
            }
        }
        dialog.setOnDismissListener {
            handler.removeCallbacks(refresh)
            if (mqttDialog === dialog) mqttDialog = null
        }
        mqttDialog = dialog
        dialog.show()
        dialog.window?.setLayout(-1, -1)
        refresh.run()
    }

    private fun renderGatewayAcks() {
        if (!::gatewayAckPanel.isInitialized) return
        val acks=getSharedPreferences("g3",0).getStringSet("gateway_acks",emptySet()) ?: emptySet()
        val expected=listOf("snapshot_upload","get_weather","login_ipbox","get_filter_sensor3","get_error_sensor3")
        gatewayAckPanel.removeAllViews()
        expected.forEach { name ->
            val received=acks.any { it.endsWith(name) }
            gatewayAckPanel.addView(TextView(this).apply {
                text=(if(received) "● " else "● ")+name+(if(received) "  已收到应答" else "  尚未确认")
                setTextColor(if(received) 0xff137333.toInt() else 0xffb3261e.toInt())
                setPadding(4,7,4,7)
            })
        }
        val count=expected.count { name -> acks.any { it.endsWith(name) } }
        gatewayAckPanel.addView(TextView(this).apply { text="已确认 $count / 5 项"; setPadding(4,10,4,8) })
    }
    private fun showGatewayAcks() {
        renderGatewayAcks()
        val acks=getSharedPreferences("g3",0).getStringSet("gateway_acks",emptySet()) ?: emptySet()
        note("网关应答进度 "+acks.size+"/5")
    }
    private fun showAccessAdvanced() {
        val panel=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(20,8,20,8) }
        panel.addView(TextView(this).apply { text="G3 蓝牙 MAC（可手动查看或修改）" })
        (bleAddress.parent as? android.view.ViewGroup)?.removeView(bleAddress)
        panel.addView(bleAddress)
        panel.addView(Button(this).apply { text="按此 MAC 直连 G3"; setOnClickListener { connectAddress() } })
        panel.addView(TextView(this).apply { text="虚拟网关 MAC（单发身份帧）"; setPadding(0,12,0,0) })
        (mac.parent as? android.view.ViewGroup)?.removeView(mac)
        panel.addView(mac)
        panel.addView(Button(this).apply { text="单独发送网关 MAC"; setOnClickListener { provision(gatewayOnly=true) } })
        android.app.AlertDialog.Builder(this).setTitle("接入高级设置").setView(panel).setPositiveButton("完成",null).show()
    }
    private fun showMigrationAdvanced() {
        val panel=LinearLayout(this).apply { orientation=LinearLayout.VERTICAL; setPadding(20,8,20,8) }
        panel.addView(TextView(this).apply { text="G3 Wi-Fi STA MAC" }); (deviceStaMac.parent as? android.view.ViewGroup)?.removeView(deviceStaMac)
        panel.addView(deviceStaMac)
        panel.addView(TextView(this).apply { text="G3 当前 IP 地址" }); (g3Ip.parent as? android.view.ViewGroup)?.removeView(g3Ip)
        panel.addView(g3Ip)
        panel.addView(TextView(this).apply { text="ESP32 固件版本标签" }); (firmwareVersion.parent as? android.view.ViewGroup)?.removeView(firmwareVersion)
        panel.addView(firmwareVersion)
        panel.addView(Button(this).apply { text="选择并校验 ESP32 raw 固件"; setOnClickListener { chooseFirmware() } })
        android.app.AlertDialog.Builder(this).setTitle("迁移高级设置").setView(panel).setPositiveButton("完成",null).show()
    }
    private fun showMcuUpgradeStatus() {
        android.app.AlertDialog.Builder(this).setTitle("屏幕 MCU 固件升级")
            .setMessage("当前 APK 已有 MCU 只读探针状态机测试，但尚未接入经过上游源码核实的 MCU 写入/升级传输适配器。为避免向屏幕 MCU 发送未经确认的命令，本按钮暂不发送升级数据。待确认设备端已上传的镜像、版本探针及真实升级接口后再启用。")
            .setPositiveButton("知道了",null).show()
        note("MCU 升级请求：当前仅有探针协调器，无真实升级传输适配器；未发送任何 MCU 命令。")
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
        if (requestCode == 302) {
            val snapshot = mqttExportSnapshot
            mqttExportSnapshot = null
            if (resultCode == RESULT_OK && data?.data != null && snapshot != null) {
                try {
                    requireNotNull(contentResolver.openOutputStream(data.data!!, "wt")).use {
                        it.write(snapshot.toByteArray(Charsets.UTF_8))
                    }
                    note("MQTT TXT 导出成功")
                } catch (e: Exception) {
                    note("MQTT TXT 导出失败：" + e.javaClass.simpleName)
                }
            }
            return
        }
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

    private fun provision(gatewayOnly: Boolean = false) {
        try {
            require(tx!=null && gatt!=null) {"未连接"}
            require(!provisioningSending && !pendingProvision && !writeInFlight) {"BLE 写入进行中"}
            val body=if(gatewayOnly) G3BlufiProtocol.buildGatewayConfig(mac.text.toString()) else G3BlufiProtocol.buildWifiConfig(ssid.text.toString(),password.text.toString(),host.text.toString().trim(),mac.text.toString())
            chunks=G3BlufiProtocol.fragment(body)
            chunkIndex=0
            note((if(gatewayOnly) "仅补发网关 MAC：" else "完整配网：")+"准备发送 "+chunks.size+" 个分片")
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
    override fun onDestroy() { mqttDialog?.dismiss(); handler.removeCallbacks(stopScanRunnable); stopScanning(); super.onDestroy();gatt?.close()}
}
