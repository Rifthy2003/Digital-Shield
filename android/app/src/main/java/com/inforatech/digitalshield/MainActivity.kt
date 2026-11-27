package com.inforatech.digitalshield

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.lifecycleScope
import com.inforatech.digitalshield.auth.KeystoreInforaTokenStore
import com.inforatech.digitalshield.oauth.InforaOAuthApiClient
import com.inforatech.digitalshield.oauth.MicrosoftOAuthManager
import com.inforatech.digitalshield.ui.ConnectedAccountsScreen
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private lateinit var oauthManager: MicrosoftOAuthManager
    private var launchedCustomTab = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val tokenStore = KeystoreInforaTokenStore(applicationContext)
        val apiClient = InforaOAuthApiClient(
            baseUrl = BuildConfig.API_BASE_URL,
            tokenStore = tokenStore,
        )
        oauthManager = MicrosoftOAuthManager(
            apiClient = apiClient,
            expectedRedirectUri = BuildConfig.MICROSOFT_ANDROID_REDIRECT_URI,
        )

        if (savedInstanceState != null) {
            launchedCustomTab = savedInstanceState.getBoolean(KEY_LAUNCHED_CUSTOM_TAB, false)
            oauthManager.restorePendingState(savedInstanceState.getString(KEY_PENDING_OAUTH_STATE))
        }

        lifecycleScope.launch { oauthManager.loadAccounts() }
        handleOAuthIntent(intent)

        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                val uiState by oauthManager.uiState.collectAsState()
                ConnectedAccountsScreen(
                    state = uiState,
                    onConnectMicrosoft = { launchMicrosoftSystemBrowser() },
                    onDisconnectAccount = { accountId ->
                        lifecycleScope.launch { oauthManager.disconnectAccount(accountId) }
                    },
                    onRefresh = {
                        lifecycleScope.launch { oauthManager.loadAccounts() }
                    },
                )
            }
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(KEY_LAUNCHED_CUSTOM_TAB, launchedCustomTab)
        outState.putString(KEY_PENDING_OAUTH_STATE, oauthManager.exportPendingState())
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleOAuthIntent(intent)
    }

    override fun onResume() {
        super.onResume()
        if (launchedCustomTab && intent?.data == null) {
            launchedCustomTab = false
            oauthManager.handleBrowserCancelled()
        }
    }

    private fun launchMicrosoftSystemBrowser() {
        lifecycleScope.launch {
            val authUrl = oauthManager.startMicrosoftAuthorization() ?: return@launch
            launchedCustomTab = true
            val customTabsIntent = CustomTabsIntent.Builder()
                .setShowTitle(true)
                .build()
            customTabsIntent.launchUrl(this@MainActivity, Uri.parse(authUrl))
        }
    }

    private fun handleOAuthIntent(intent: Intent?) {
        val data = intent?.data ?: return
        launchedCustomTab = false
        intent.data = null
        lifecycleScope.launch {
            oauthManager.handleCallbackUri(data.toString())
        }
    }

    companion object {
        private const val KEY_LAUNCHED_CUSTOM_TAB = "launched_custom_tab"
        private const val KEY_PENDING_OAUTH_STATE = "pending_oauth_state"
    }
}
