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
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
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
 * ops: eid info list notifications download enable disable delete reset
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
                if (backend == "fw") runFramework(op, out) else runLpac(op, out)
                out.put("ok", true)
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
            else -> error("unknown op: $op")
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
        val pi = PendingIntent.getBroadcast(this, 0, Intent(actionName),
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        action(pi)
        val code = done.await()
        runCatching { unregisterReceiver(rx) }
        return code
    }

    private fun requireExtra(k: String): String =
        intent.getStringExtra(k) ?: error("missing --es $k")
}
