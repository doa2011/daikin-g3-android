package io.github.doa2011.g3provision

import org.junit.Assert.*
import org.junit.Test
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.io.DataInputStream
import java.io.DataOutputStream

class DnsSocketRegressionTest {
    private fun query(): ByteArray {
        val buf = java.io.ByteArrayOutputStream()
        DataOutputStream(buf).use { o ->
            o.writeShort(123); o.writeShort(0x100); o.writeShort(1)
            repeat(3) { o.writeShort(0) }
            for (label in "newlifemulti.daikin-china.com.cn".split('.')) {
                o.writeByte(label.length); o.writeBytes(label)
            }
            o.writeByte(0); o.writeShort(1); o.writeShort(1)
        }
        return buf.toByteArray()
    }
    @Test fun actualUdpAndTcpListeners() {
        val port = ServerSocket(0).use { it.localPort }
        val service = DnsRedirectServer("127.0.0.1","192.168.1.1",port)
        service.start()
        try {
            val q = query()
            val loop = InetAddress.getByName("127.0.0.1")
            DatagramSocket().use { s ->
                s.soTimeout = 3000
                s.send(DatagramPacket(q,q.size,loop,port))
                val p = DatagramPacket(ByteArray(512),512); s.receive(p)
                assertArrayEquals(byteArrayOf(192.toByte(),168.toByte(),1,1),p.data.copyOf(p.length).takeLast(4).toByteArray())
            }
            Socket(loop,port).use { s ->
                s.soTimeout = 3000
                val out = DataOutputStream(s.getOutputStream()); out.writeShort(q.size); out.write(q); out.flush()
                val input = DataInputStream(s.getInputStream()); val response = ByteArray(input.readUnsignedShort()); input.readFully(response)
                assertEquals(1,response[7].toInt())
            }
        } finally { service.stop() }
    }
    @Test fun stopReleasesBothListenersForRestart() {
        val port = ServerSocket(0).use { it.localPort }
        val service = DnsRedirectServer("127.0.0.1","192.168.1.1",port)
        repeat(2) {
            service.start()
            service.stop()
            ServerSocket(port).use { assertEquals(port,it.localPort) }
            DatagramSocket(port).use { assertEquals(port,it.localPort) }
        }
    }
    @Test fun occupiedTcpPortReleasesUdpOnFailure() {
        ServerSocket(0).use { blocker ->
            val port = blocker.localPort
            val service = DnsRedirectServer("127.0.0.1","192.168.1.1",port)
            try { service.start(); fail("occupied port accepted") } catch (_: java.net.BindException) {}
            finally { service.stop() }
            DatagramSocket(port).use { assertEquals(port,it.localPort) }
        }
    }
}
