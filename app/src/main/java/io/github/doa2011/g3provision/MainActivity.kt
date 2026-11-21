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
    private lateinit var ssid: EditText
    private lateinit var password: EditText
    private lateinit var host: EditText
    private lateinit var mac: EditText
    private lateinit var output: TextView
    private fun note(s: String) { runOnUiThread { output.append(s + "\n") } }
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(20,20,20,20) }
        fun field(h: String, initial: String = ""): EditText = EditText(this).apply { hint=h; setText(initial); layout.addView(this) }
        selector = Spinner(this); layout.addView(selector)
        ssid = field("2.4GHz Wi-Fi SSID"); password = field("Wi-Fi 密码")
        host = field("Windows LAN IPv4"); mac = field("虚拟网关 MAC", "020000000001")
        layout.addView(Button(this).apply { text="扫描全部 BLE 设备"; setOnClickListener { scan() } })
        layout.addView(Button(this).apply { text="连接 G3"; setOnClickListener { connect() } })
        layout.addView(Button(this).apply { text="发送配网（不刷机）"; setOnClickListener { provision() } })
        output=TextView(this); layout.addView(ScrollView(this).apply { addView(output) },LinearLayout.LayoutParams(-1,0,1f))
        setContentView(layout); note("仅 BLE 配网，不执行 OTA")
    }
    private fun permitted(): Boolean {
        val p=if(Build.VERSION.SDK_INT>=31) arrayOf(Manifest.permission.BLUETOOTH_SCAN,Manifest.permission.BLUETOOTH_CONNECT)
            else arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        val missing=p.filter { checkSelfPermission(it)!=PackageManager.PERMISSION_GRANTED }
        if(missing.isNotEmpty()) { requestPermissions(missing.toTypedArray(),100); return false }
        return true
    }
    private fun refreshDevices() {
        val selected = selector.selectedItemPosition
        selector.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, deviceLabels.values.toList())
        if (selected in deviceLabels.indices) selector.setSelection(selected)
    }
    private val scanner=object: ScanCallback() {
        override fun onScanResult(callbackType:Int,result:ScanResult) {
            val address = result.device.address
            val name = result.scanRecord?.deviceName
                ?: try { result.device.name } catch (_: SecurityException) { null }
            val display = name?.takeIf { it.isNotBlank() } ?: "未命名设备"
            scanCount++
            if (devices.put(address, result.device) == null || deviceLabels[address] != "$display ($address, RSSI ${result.rssi})") {
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
        stopScanning()
        tx=null;seq=0;chunks=emptyList();gatt?.close()
        note("连接 "+addr)
        gatt=devices[addr]?.connectGatt(this,false,callbacks,BluetoothDevice.TRANSPORT_LE)
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
        if(chunkIndex>=chunks.size) {chunks=emptyList();note("发送完毕，需检查 DHCP 确认上线");return}
        val i=chunkIndex++;send(0x4d,chunks[i],if(i<chunks.lastIndex)0x10 else 0)
        handler.postDelayed({sendChunks()},600)
    }
    override fun onDestroy() { handler.removeCallbacks(stopScanRunnable); stopScanning(); super.onDestroy();gatt?.close()}
}
