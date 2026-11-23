package io.github.doa2011.g3provision

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Typeface
import android.widget.*
import android.text.InputType
import org.json.*
import org.msgpack.core.MessagePack
import org.msgpack.core.MessagePacker
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private val reads = listOf("status.get","diagnostics.get","screen.log.get","screen.recovery.get","config.get","screen.boot.result.get")
    private lateinit var target: EditText
    private lateinit var action: AutoCompleteTextView
    private lateinit var params: EditText
    private lateinit var user: EditText
    private lateinit var password: EditText
    private lateinit var output: TextView
    private lateinit var interval: Spinner
    private lateinit var poll: Button
    private val handler = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var busy = false
    private var polling = false
    private var closed = false
    private val log = StringBuilder()
    private data class Request(val url: String,val action: String,val params: JSONObject,val auth: String)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply { orientation=1; setPadding(24,24,24,24) }
        val scroll=ScrollView(this).apply { addView(root) }
        setContentView(scroll)
        fun label(s:String) { root.addView(TextView(this).apply { text=s; textSize=14f }) }
        fun field(s:String,v:String=""):EditText { label(s); return EditText(this).apply { setText(v); setSingleLine(true); root.addView(this) } }
        fun button(s:String,fn:()->Unit):Button = Button(this).apply { text=s; setOnClickListener { fn() }; root.addView(this) }
        root.addView(TextView(this).apply { text="G3 Debug"; textSize=26f; setTypeface(null,Typeface.BOLD) })
        target=field("调试目标",getPreferences(0).getString("target","http://192.168.99.155") ?: "")
        label("命令（可手动输入）")
        action=AutoCompleteTextView(this).apply { setAdapter(ArrayAdapter(this@MainActivity,android.R.layout.simple_dropdown_item_1line,reads)); threshold=0; setText("status.get"); setOnClickListener { showDropDown() }; root.addView(this) }
        params=field("JSON 参数","{}").apply { setSingleLine(false); minLines=2 }
        user=field("用户名（可选）")
        password=field("密码（不保存）").apply { inputType=InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD }
        button("发送命令") { submit(false) }
        button("全部诊断") { submit(true) }
        interval=Spinner(this).apply { adapter=ArrayAdapter(this@MainActivity,android.R.layout.simple_spinner_dropdown_item,listOf("1 秒","2 秒","5 秒","10 秒","30 秒")); setSelection(1); root.addView(this) }
        poll=button("开始只读轮询") { if(polling) stopPoll() else if(action.text.toString() in reads) { polling=true; poll.text="停止轮询"; submit(false) } else toast("仅允许只读命令轮询") }
        button("复制结果") { (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("G3 Debug",log.toString())); toast("已复制") }
        button("分享结果") { startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply { type="text/plain"; putExtra(Intent.EXTRA_TEXT,log.toString()) },"分享诊断")) }
        button("清空结果") { log.clear(); output.text="" }
        label("返回结果")
        output=TextView(this).apply { typeface=Typeface.MONOSPACE; textSize=13f; setTextIsSelectable(true); root.addView(this) }
    }
    private fun toast(s:String) { Toast.makeText(this,s,Toast.LENGTH_SHORT).show() }
    private fun stopPoll() { polling=false; handler.removeCallbacksAndMessages(null); poll.text="开始只读轮询" }
    override fun onStop() { stopPoll(); super.onStop() }
    override fun onDestroy() { closed=true; worker.shutdownNow(); super.onDestroy() }
    private fun append(s:String) { log.append(s).append("\n"); if(log.length>200000) log.delete(0,log.length-200000); output.text=log.toString() }
    private fun submit(all:Boolean) {
        if(busy) { if(polling) handler.postDelayed({submit(false)},500); return }
        val reqs=try {
            var base=target.text.toString().trim().trimEnd('/')
            if(!base.contains("://")) base="http://"+base
            val url=URL(base)
            require(url.protocol in listOf("http","https") && url.host.isNotBlank() && url.userInfo==null && url.query==null && url.ref==null && url.path.isEmpty())
            val cmd=action.text.toString().trim(); require(cmd.isNotEmpty())
            val auth=if(user.text.isNotEmpty()) android.util.Base64.encodeToString((user.text.toString()+":"+password.text.toString()).toByteArray(),android.util.Base64.NO_WRAP) else ""
            getPreferences(0).edit().putString("target",base).apply()
            if(all) reads.take(4).map { Request(base,it,JSONObject(),auth) } else listOf(Request(base,cmd,JSONObject(params.text.toString().ifBlank{"{}"}),auth))
        } catch(e:Exception) { stopPoll(); toast("地址或 JSON 参数无效"); return }
        if(polling && reqs.any { it.action !in reads }) { stopPoll(); return }
        if(reqs.any { it.action !in reads }) {
            AlertDialog.Builder(this).setTitle("确认执行非只读命令").setMessage(reqs.first().action).setNegativeButton("取消",null).setPositiveButton("执行"){_,_-> execute(reqs)}.show()
        } else execute(reqs)
    }
    private fun execute(reqs:List<Request>) {
        if(busy || closed) return
        busy=true
        worker.execute {
            for(r in reqs) {
                val result=try { call(r) } catch(e:Exception) { "ERROR: "+e.toString() }
                handler.post { if(!closed) append("========== "+r.action+" ==========\n"+result) }
            }
            handler.post { busy=false; if(!closed && polling) handler.postDelayed({submit(false)},listOf(1000L,2000L,5000L,10000L,30000L)[interval.selectedItemPosition]) }
        }
    }
    private fun pack(p:MessagePacker,v:Any?) {
        when(v) {
            null,JSONObject.NULL -> p.packNil()
            is JSONObject -> { p.packMapHeader(v.length()); val keys=v.keys(); while(keys.hasNext()){val k=keys.next();p.packString(k);pack(p,v.get(k))} }
            is JSONArray -> { p.packArrayHeader(v.length()); for(i in 0 until v.length()) pack(p,v.get(i)) }
            is Boolean -> p.packBoolean(v)
            is Int -> p.packInt(v)
            is Long -> p.packLong(v)
            is Number -> p.packDouble(v.toDouble())
            else -> p.packString(v.toString())
        }
    }
    private fun call(r:Request):String {
        val p=MessagePack.newDefaultBufferPacker()
        val body=p.use { pack(it,JSONObject().put("request_id",UUID.randomUUID().toString().replace("-","")).put("action",r.action).put("params",r.params)); it.toByteArray() }
        val c=URL(r.url+"/api/v1/command").openConnection() as HttpURLConnection
        val start=System.currentTimeMillis()
        try {
            c.requestMethod="POST"; c.instanceFollowRedirects=false; c.connectTimeout=8000; c.readTimeout=8000; c.doOutput=true
            c.setRequestProperty("Content-Type","application/msgpack")
            if(r.auth.isNotEmpty()) c.setRequestProperty("Authorization","Basic "+r.auth)
            c.outputStream.use { it.write(body) }
            val code=c.responseCode
            val bytes=(if(code>=400)c.errorStream else c.inputStream)?.use { input -> val out=java.io.ByteArrayOutputStream(); val b=ByteArray(4096); while(out.size()<262144){val n=input.read(b,0,minOf(b.size,262144-out.size()));if(n<0)break;out.write(b,0,n)};out.toByteArray() } ?: byteArrayOf()
            val raw=if(code in 200..299) try { MessagePack.newDefaultUnpacker(bytes).use { it.unpackValue().toJson() } } catch(e:Exception){String(bytes,Charsets.UTF_8)} else String(bytes,Charsets.UTF_8)
            val pretty=try { JSONObject(raw).toString(2) } catch(e:Exception){raw}
            return "HTTP "+code+" · "+(System.currentTimeMillis()-start)+" ms\n"+pretty
        } finally { c.disconnect() }
    }
}
