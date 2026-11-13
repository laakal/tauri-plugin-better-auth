package io.github.laakal.betterauth

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.appcompat.app.AppCompatActivity
import androidx.browser.customtabs.CustomTabsIntent
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.Plugin

@InvokeArg
class OpenAuthArgs {
    lateinit var url: String
}

/**
 * Opens the sign-in page in a Custom Tab (or the default browser when none
 * supports Custom Tabs).
 *
 * The `<scheme>://…` callback comes back as an intent to the app's activity,
 * which tauri-plugin-deep-link delivers; this plugin does not handle it.
 */
@TauriPlugin
class BetterAuthPlugin(private val activity: Activity) : Plugin(activity) {
    /** A tab was opened and the app's activity has not been shown since. */
    @Volatile
    private var tabOpen = false

    @Command
    fun openAuth(invoke: Invoke) {
        val args = invoke.parseArgs(OpenAuthArgs::class.java)
        val uri = Uri.parse(args.url)
        activity.runOnUiThread {
            try {
                CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(activity, uri)
                tabOpen = true
                invoke.resolve()
            } catch (error: ActivityNotFoundException) {
                invoke.reject("No browser is available to open the sign-in page.")
            }
        }
    }

    /**
     * Closes the tab. It sits above the app's activity in the same task, so
     * bringing that activity back to the top removes it.
     */
    @Command
    fun closeAuth(invoke: Invoke) {
        activity.runOnUiThread {
            if (tabOpen) {
                tabOpen = false
                activity.startActivity(
                    Intent(activity, activity.javaClass)
                        .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                )
            }
            invoke.resolve()
        }
    }

    override fun onResume(activity: AppCompatActivity) {
        tabOpen = false
    }
}
