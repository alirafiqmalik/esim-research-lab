package im.angry.openeuicc.ui

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Bundle
import android.telephony.euicc.DownloadableSubscription
import android.telephony.euicc.EuiccManager
import android.util.Log
import androidx.lifecycle.lifecycleScope
import im.angry.openeuicc.core.EuiccChannel
import im.angry.openeuicc.service.EuiccChannelManagerService.Companion.waitDone
import im.angry.openeuicc.util.decodeHex
import im.angry.openeuicc.util.encodeHex
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import net.typeblog.lpac_jni.ProfileDownloadInput
import org.json.JSONArray
import org.json.JSONObject

/**
 * Headless, exported activity that runs one eSIM operation and logs a JSON
 * result to the "ESIMCTL" logcat tag, then finishes. Drives OpenEUICC's own
 * lpac stack (full plaintext) OR the Android framework EuiccManager.
 *
 *   adb shell am start -n im.angry.openeuicc/.ui.EsimCtlActivity \
 *       --es id <reqid> --es op <op> [--es backend lpac|fw] [--es code ...] [--es iccid ...]
 *
 * ops: eid info list notifications download enable disable delete
 *      nickname remove-notification handle-notification reset
 *      apdu get-addresses set-dp-address get-rat   (raw ES10x, ISD-R store-data)
 * Result line: `ESIMCTL: <id> RESULT <json>`  (json has ok/op/... )
 */
class EsimCtlActivity : BaseEuiccAccessActivity() {
    companion object {
        private const val TAG = "ESIMCTL"
    }

    private lateinit var reqId: String

    override fun onCreate(savedInstanceState: Bundle?) {
        reqId = intent.getStringExtra("id") ?: "-"
        super.onCreate(savedInstanceState)  // binds the service; onInit() fires when ready
    }

    // Called by BaseEuiccAccessActivity once euiccChannelManager is initialized.
    override fun onInit() {
        val op = intent.getStringExtra("op") ?: "noop"
        val backend = intent.getStringExtra("backend") ?: "lpac"
        Log.i(TAG, "$reqId START op=$op backend=$backend")
        lifecycleScope.launch {
            val out = JSONObject().put("op", op).put("backend", backend)
            try {
                when (backend) {
                    "fw" -> runFramework(op, out)
                    "card" -> runCard(op, out)
                    else -> runLpac(op, out)
                }
                // fw/card action ops carry a framework resultCode (0 = OK); treat non-zero as
                // failure so `ok` and esimctl exit codes match the lpac backend's semantics.
                val rc = if (out.has("resultCode")) out.getInt("resultCode") else 0
                if (!out.has("ok")) out.put("ok", rc == 0)
            } catch (e: Throwable) {
                // keep the line under logcat's ~4KB limit (download exceptions dump byte arrays)
                val msg = e.toString().let { if (it.length > 400) it.substring(0, 400) + "…" else it }
                out.put("ok", false).put("error", msg)
            }
            Log.i(TAG, "$reqId RESULT $out")
            finish()
        }
    }

    private suspend fun internalPort(): Pair<Int, Int> =
        euiccChannelManager.flowInternalEuiccPorts().first()

    private val seId get() = EuiccChannel.SecureElementId.DEFAULT

    // ---- lpac backend: OpenEUICC's own LocalProfileAssistant / task runner ----
    private suspend fun runLpac(op: String, out: JSONObject) {
        val (slot, port) = internalPort()
        out.put("slot", slot).put("port", port)
        when (op) {
            "eid" -> out.put("eid", euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.eID })
            "info" -> euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
                out.put("eid", ch.lpa.eID)
                ch.lpa.euiccInfo2?.let { out.put("euiccInfo2", it.toString()) }
            }
            "list" -> {
                val arr = JSONArray()
                euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
                    ch.lpa.profiles.forEach { p ->
                        arr.put(JSONObject()
                            .put("iccid", p.iccid)
                            .put("name", p.name)
                            .put("nickname", p.nickName)
                            .put("provider", p.providerName)
                            .put("state", p.state.toString())
                            .put("class", p.profileClass.toString()))
                    }
                }
                out.put("profiles", arr).put("count", arr.length())
            }
            "notifications" -> {
                val arr = JSONArray()
                euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
                    ch.lpa.notifications.forEach { n ->
                        arr.put(JSONObject()
                            .put("seq", n.seqNumber)
                            .put("iccid", n.iccid)
                            .put("operation", n.profileManagementOperation.toString()))
                    }
                }
                out.put("notifications", arr).put("count", arr.length())
            }
            "download" -> {
                val code = requireExtra("code")
                val m = Regex("^(?:LPA:)?1\\$([^$]+)\\$([^$]*)", RegexOption.IGNORE_CASE)
                    .find(code) ?: error("bad activation code: $code")
                val imei = intent.getStringExtra("imei")
                euiccChannelManagerService.waitForForegroundTask()
                val err = euiccChannelManagerService.launchProfileDownloadTask(
                    slot, port, seId,
                    ProfileDownloadInput(m.groupValues[1], m.groupValues[2].ifBlank { null }, imei, null)
                ).waitDone()
                out.put("smdp", m.groupValues[1]).put("matchingId", m.groupValues[2])
                if (err != null) throw err
            }
            "enable", "disable" -> {
                val iccid = requireExtra("iccid")
                euiccChannelManagerService.waitForForegroundTask()
                val err = euiccChannelManagerService.launchProfileSwitchTask(
                    slot, port, seId, iccid, op == "enable", reconnectTimeoutMillis = 30_000
                ).waitDone()
                out.put("iccid", iccid)
                if (err != null) throw err
            }
            "delete" -> {
                val iccid = requireExtra("iccid")
                euiccChannelManagerService.waitForForegroundTask()
                val err = euiccChannelManagerService
                    .launchProfileDeleteTask(slot, port, seId, iccid).waitDone()
                out.put("iccid", iccid)
                if (err != null) throw err
            }
            "nickname" -> {
                val iccid = requireExtra("iccid")
                val name = requireExtra("name")
                euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.setNickname(iccid, name) }
                out.put("iccid", iccid).put("nickname", name)
            }
            "remove-notification" -> {
                val seq = requireExtra("seq").toLong()
                val ok = euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.deleteNotification(seq) }
                out.put("seq", seq).put("removed", ok)
            }
            "handle-notification" -> {
                val seq = requireExtra("seq").toLong()
                val ok = euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.handleNotification(seq) }
                out.put("seq", seq).put("handled", ok)
            }
            "reset" -> {
                // euiccMemoryReset() erases ALL profiles — require an explicit confirm token.
                if (intent.getStringExtra("confirm") != "RESET")
                    error("euiccMemoryReset wipes ALL profiles; refusing without --es confirm RESET")
                euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.euiccMemoryReset() }
                out.put("reset", true)
            }
            "discovery" -> { // ES11 SM-DS discovery (challenge → initiateAuth → authServer → es11)
                val smds = intent.getStringExtra("smds") ?: "lpa.ds.gsma.com"
                val events = euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.discovery(smds) }
                out.put("smds", smds)
                    .put("events", JSONArray().apply { events.forEach { put(it) } })
                    .put("count", events.size)
            }
            "authenticate" -> { // standalone AuthenticateServer CI-trust probe (no download)
                val server = requireExtra("server")
                val rc = euiccChannelManager.withEuiccChannel(slot, port, seId) { it.lpa.authenticateServer(server) }
                out.put("server", server).put("authRc", rc).put("ciTrusted", rc == 0)
                    .put("stage", when (rc) {
                        0 -> "accepted"; -1 -> "challenge_failed"
                        -2 -> "initiateAuthentication_failed"; -3 -> "authenticateServer_rejected"
                        else -> "unknown"
                    })
            }
            // ---- raw ES10x over the ISD-R (store-data), for commands lpac-jni does not bridge ----
            "apdu" -> {
                val apdu = requireExtra("hex").replace(" ", "")
                out.put("apdu", apdu).put("resp", isdrExchange(slot, port, apdu.decodeHex()).encodeHex())
            }
            "get-addresses" -> // ES10a GetEuiccConfiguredAddresses (BF3C)
                out.put("resp", isdrExchange(slot, port, storeData(byteArrayOf(0xBF.toByte(), 0x3C, 0x00))).encodeHex())
            "get-rat" -> // ES10b GetRAT (BF43)
                out.put("resp", isdrExchange(slot, port, storeData(byteArrayOf(0xBF.toByte(), 0x43, 0x00))).encodeHex())
            "set-dp-address" -> { // ES10a SetDefaultDpAddress (BF3F): defaultDpAddress [0] UTF8String
                val addr = requireExtra("address").toByteArray(Charsets.UTF_8)
                val inner = byteArrayOf(0x80.toByte(), addr.size.toByte()) + addr
                val cmd = byteArrayOf(0xBF.toByte(), 0x3F.toByte(), inner.size.toByte()) + inner
                out.put("address", requireExtra("address"))
                    .put("resp", isdrExchange(slot, port, storeData(cmd)).encodeHex())
            }
            "info1" -> // ES10b GetEUICCInfo1 (BF20): version + CI PKID lists, no download
                out.put("resp", isdrExchange(slot, port, storeData(byteArrayOf(0xBF.toByte(), 0x20, 0x00))).encodeHex())
            "challenge" -> // ES10b GetEUICCChallenge (BF2E): a fresh 16-byte SE challenge
                out.put("resp", isdrExchange(slot, port, storeData(byteArrayOf(0xBF.toByte(), 0x2E, 0x00))).encodeHex())
            "retrieve-notification" -> { // ES10b RetrieveNotificationsList (BF2B) by seqNumber
                val seq = requireExtra("seq").toLong()
                val i80 = byteArrayOf(0x80.toByte()) + der(derInt(seq))          // seqNumber [0]
                val a0 = byteArrayOf(0xA0.toByte()) + der(i80)                    // searchCriteria [0]
                val cmd = byteArrayOf(0xBF.toByte(), 0x2B.toByte()) + der(a0)
                out.put("seq", seq).put("resp", isdrExchange(slot, port, storeData(cmd)).encodeHex())
            }
            // ---- a DIFFERENT applet: open a fresh logical channel to the given AID ----
            // (allowed — the non-multiselectable limit is per-applet, only a 2nd ISD-R channel fails)
            "apdu-aid" -> {
                val aid = requireExtra("aid").replace(" ", "")
                val apdu = requireExtra("hex").replace(" ", "")
                out.put("aid", aid).put("apdu", apdu)
                    .put("resp", aidExchange(slot, port, aid.decodeHex()) { it(apdu.decodeHex()) }.encodeHex())
            }
            "select-aid" -> { // open a channel to AID; return its SELECT response (FCI)
                val aid = requireExtra("aid").replace(" ", "")
                out.put("aid", aid).put("selectResponse", aidSelect(slot, port, aid.decodeHex()).encodeHex())
            }
            else -> error("unknown op: $op")
        }
    }

    // Transmit one raw command APDU to the ISD-R. The ISD-R is non-multiselectable,
    // so a second logical channel is refused (SW 6999); lpac already holds the one
    // permitted channel open for the context lifetime — reuse that handle. OMAPI's
    // Channel.transmit handles 61xx GET RESPONSE, so this returns data+SW.
    private suspend fun isdrExchange(slot: Int, port: Int, apdu: ByteArray): ByteArray =
        euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
            val omapi = ch.apduInterface
            val field = omapi.javaClass.getDeclaredField("channels").apply { isAccessible = true }
            @Suppress("UNCHECKED_CAST")
            val handle = (field.get(omapi) as Map<Int, *>).keys.firstOrNull()
            if (handle != null) omapi.transmit(handle, apdu)
            else omapi.withLogicalChannel(ch.isdrAid) { it(apdu) }
        }

    // Wrap a BER-TLV payload in an ES10x STORE DATA command (81 E2 91 00 Lc <tlv>).
    private fun storeData(tlv: ByteArray): ByteArray =
        byteArrayOf(0x81.toByte(), 0xE2.toByte(), 0x91.toByte(), 0x00, tlv.size.toByte()) + tlv

    // BER short-form length + value (payloads here are always < 128 bytes).
    private fun der(value: ByteArray): ByteArray = byteArrayOf(value.size.toByte()) + value

    // Minimal positive DER INTEGER content bytes (prepend 0x00 if the top bit is set).
    private fun derInt(v: Long): ByteArray {
        if (v == 0L) return byteArrayOf(0)
        val bytes = ArrayDeque<Byte>()
        var n = v
        while (n > 0) { bytes.addFirst((n and 0xFF).toByte()); n = n shr 8 }
        if (bytes.first().toInt() and 0x80 != 0) bytes.addFirst(0)
        return bytes.toByteArray()
    }

    // Open a FRESH logical channel to an arbitrary AID (ECASD, ARA-M, ISD-P …) and
    // run a callback on it. Selecting a different applet is allowed even while the
    // ISD-R channel is held — the non-multiselectable limit is per-applet.
    private suspend fun <T> aidExchange(slot: Int, port: Int, aid: ByteArray,
                                        cb: ((ByteArray) -> ByteArray) -> T): T =
        euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
            ch.apduInterface.withLogicalChannel(aid, cb)
        }

    // Open a channel to an AID and return its SELECT response (FCI) via the OMAPI Channel.
    private suspend fun aidSelect(slot: Int, port: Int, aid: ByteArray): ByteArray =
        euiccChannelManager.withEuiccChannel(slot, port, seId) { ch ->
            val omapi = ch.apduInterface
            val handle = omapi.logicalChannelOpen(aid)
            try {
                val field = omapi.javaClass.getDeclaredField("channels").apply { isAccessible = true }
                @Suppress("UNCHECKED_CAST")
                val channel = (field.get(omapi) as Map<Int, *>).getValue(handle)!!
                channel.javaClass.getMethod("getSelectResponse").invoke(channel) as ByteArray
            } finally {
                omapi.logicalChannelClose(handle)
            }
        }

    // ---- fw backend: Android framework EuiccManager ----
    private suspend fun runFramework(op: String, out: JSONObject) {
        val em = getSystemService(EuiccManager::class.java)
            ?: error("EuiccManager unavailable")
        when (op) {
            "eid" -> out.put("eid", em.eid)
            "info" -> out.put("eid", em.eid).put("available", em.isEnabled)
            "download" -> {
                val sub = DownloadableSubscription.forActivationCode(requireExtra("code"))
                out.put("resultCode", awaitEuicc { pi -> em.downloadSubscription(sub, true, pi) })
            }
            "delete" -> out.put("resultCode",
                awaitEuicc { pi -> em.deleteSubscription(requireExtra("subId").toInt(), pi) })
            "switch" -> out.put("resultCode",
                awaitEuicc { pi -> em.switchToSubscription(requireExtra("subId").toInt(), pi) })
            else -> error("fw backend does not support op: $op")
        }
    }

    private suspend fun awaitEuicc(action: (PendingIntent) -> Unit): Int {
        val actionName = "im.angry.openeuicc.ESIMCTL_FW_RESULT.$reqId"
        val done = CompletableDeferred<Int>()
        val rx = object : BroadcastReceiver() {
            override fun onReceive(c: Context, i: Intent) {
                done.complete(resultCode)
            }
        }
        registerReceiver(rx, IntentFilter(actionName), Context.RECEIVER_EXPORTED)
        // explicit (setPackage) so a FLAG_MUTABLE PendingIntent is allowed on Android 14+ (U);
        // EuiccManager needs it mutable to fill in the result extras.
        val pi = PendingIntent.getBroadcast(this, 0,
            Intent(actionName).setPackage(packageName),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        action(pi)
        val code = done.await()
        runCatching { unregisterReceiver(rx) }
        return code
    }

    private fun requireExtra(k: String): String =
        intent.getStringExtra(k) ?: error("missing --es $k")

    // ---- card backend: the framework's per-command IEuiccCardController path ----
    // Reached through the in-process android.telephony.euicc.EuiccCardManager wrapper
    // (hidden @SystemApi) via reflection — its ResultCallback is a plain interface, so a
    // dynamic Proxy works (the raw AIDL .Stub callbacks would have to cross binder and
    // cannot be proxied). This is a SECOND, independent ES10 command path through the
    // stock Google card stack, parallel to lpac. OpenEUICC holds WRITE_EMBEDDED_SUBSCRIPTIONS.
    private suspend fun runCard(op: String, out: JSONObject) {
        val method = when (op) {
            "challenge" -> "requestEuiccChallenge"
            "info1" -> "requestEuiccInfo1"
            "info2", "info" -> "requestEuiccInfo2"
            "default-smdp" -> "requestDefaultSmdpAddress"
            "smds" -> "requestSmdsAddress"
            "rat" -> "requestRulesAuthTable"
            "profiles", "list" -> "requestAllProfiles"
            "eid" -> return runCardEid(out)
            else -> error("card backend does not support op: $op")
        }
        cardCall(method, out)
    }

    private fun runCardEid(out: JSONObject) {
        // EID is a plain EuiccManager read; expose it under the card backend for parity.
        out.put("eid", getSystemService(EuiccManager::class.java)?.eid)
    }

    // On this build EuiccCardController keys cards by a STRING cardId; the eUICC's is
    // its EID. (Accessors are @hide — reflect them.)
    private fun cardIdString(): String =
        intent.getStringExtra("cardId")
            ?: getSystemService(EuiccManager::class.java)?.eid ?: error("no eUICC EID for cardId")

    private suspend fun cardCall(method: String, out: JSONObject) {
        val cardId = cardIdString()
        val ecmCls = Class.forName("android.telephony.euicc.EuiccCardManager")
        val ecm = ecmCls.getDeclaredConstructor(Context::class.java)
            .apply { isAccessible = true }.newInstance(this)
        val rcCls = Class.forName("android.telephony.euicc.EuiccCardManager\$ResultCallback")
        val resultOk = runCatching { ecmCls.getField("RESULT_OK").getInt(null) }.getOrDefault(0)

        val done = CompletableDeferred<Pair<Int, Any?>>()
        val cb = java.lang.reflect.Proxy.newProxyInstance(rcCls.classLoader, arrayOf(rcCls)) { _, m, args ->
            if (m.name == "onComplete" && !done.isCompleted)
                done.complete(Pair(args[0] as Int, args.getOrNull(1)))
            null
        }
        val executor = java.util.concurrent.Executor { it.run() }

        // read methods here are all (String cardId, Executor, ResultCallback)
        val fn = ecmCls.methods.first { it.name == method && it.parameterTypes.lastOrNull() == rcCls }
        fn.invoke(ecm, cardId, executor, cb)

        val (rc, res) = withTimeoutOrNull(30_000) { done.await() }
            ?: error("card call '$method' timed out")
        val rcName = ecmCls.fields.firstOrNull {
            java.lang.reflect.Modifier.isStatic(it.modifiers) &&
                it.type == Int::class.javaPrimitiveType &&
                it.name.startsWith("RESULT_") && it.getInt(null) == rc
        }?.name
        out.put("cardId", cardId).put("method", method)
            .put("resultCode", rc).put("resultName", rcName ?: JSONObject.NULL)
        when (res) {
            null -> out.put("result", JSONObject.NULL)
            is ByteArray -> out.put("result", res.encodeHex())
            is Array<*> -> out.put("result", JSONArray().apply { res.forEach { put(it?.toString()) } })
            else -> out.put("result", res.toString())
        }
        out.put("ok", rc == resultOk)
    }
}
