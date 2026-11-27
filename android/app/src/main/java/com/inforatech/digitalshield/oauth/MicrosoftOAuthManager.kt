package com.inforatech.digitalshield.oauth

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

data class ConnectedAccountsUiState(
    val accounts: List<ConnectedAccount> = emptyList(),
    val isLoading: Boolean = false,
    val isConnecting: Boolean = false,
    val disconnectingAccountId: String? = null,
    val statusMessage: String? = null,
    val errorMessage: String? = null,
)

/**
 * Coordinates Android Microsoft Personal Account OAuth linking via system browser + PKCE.
 *
 * Security properties:
 * - Never embeds or sends a client secret.
 * - Never stores Microsoft access or refresh tokens on the device.
 * - Tracks pending `state` in memory only and consumes it atomically before calling `/callback`
 *   to block duplicate callback replays and CSRF.
 */
class MicrosoftOAuthManager(
    private val apiClient: OAuthBackendClient,
    private val expectedRedirectUri: String,
) {
    private val _uiState = MutableStateFlow(ConnectedAccountsUiState())
    val uiState: StateFlow<ConnectedAccountsUiState> = _uiState.asStateFlow()

    @Volatile
    private var pendingState: String? = null

    @Volatile
    private var callbackInFlight: Boolean = false

    val hasPendingAuthorization: Boolean
        get() = pendingState != null

    fun exportPendingState(): String? = pendingState

    fun restorePendingState(savedState: String?) {
        if (!savedState.isNullOrBlank() && pendingState == null) {
            pendingState = savedState
            _uiState.update { it.copy(isConnecting = true) }
        }
    }

    suspend fun loadAccounts() {
        _uiState.update { it.copy(isLoading = true, errorMessage = null) }
        try {
            val all = apiClient.listConnectedAccounts()
            _uiState.update { it.copy(accounts = all, isLoading = false) }
        } catch (e: OAuthApiException) {
            _uiState.update { it.copy(isLoading = false, errorMessage = e.message) }
        }
    }

    /**
     * Initiates Android Microsoft OAuth by requesting a backend-generated authorization URL
     * containing PKCE S256 challenge and single-use state.
     */
    suspend fun startMicrosoftAuthorization(): String? {
        if (_uiState.value.isConnecting || callbackInFlight) return null
        _uiState.update { it.copy(isConnecting = true, errorMessage = null, statusMessage = null) }
        return try {
            val auth = apiClient.authorizeMicrosoft()
            val params = parseQueryParameters(URI(auth.authorizationUrl).rawQuery)
            val state = params["state"]
            val pkceMethod = params["code_challenge_method"]
            if (state.isNullOrBlank() || pkceMethod != "S256") {
                throw OAuthApiException(500, "Invalid authorization URL returned by server.")
            }
            pendingState = state
            auth.authorizationUrl
        } catch (e: OAuthApiException) {
            pendingState = null
            _uiState.update { it.copy(isConnecting = false, errorMessage = e.message) }
            null
        } catch (_: Exception) {
            pendingState = null
            _uiState.update {
                it.copy(isConnecting = false, errorMessage = "Unable to start Microsoft linking.")
            }
            null
        }
    }

    /**
     * Handles the redirect URI returned by Chrome Custom Tabs / Android App Link.
     */
    suspend fun handleCallbackUri(rawRedirectUri: String): OAuthCallbackOutcome {
        if (callbackInFlight) {
            return OAuthCallbackOutcome.Failed("OAuth callback is already in progress.")
        }

        val expectedUri = runCatching { URI(expectedRedirectUri) }.getOrNull()
        val actualUri = runCatching { URI(rawRedirectUri) }.getOrNull()
        if (expectedUri == null || actualUri == null || !matchesRedirectBase(expectedUri, actualUri)) {
            clearPendingAuth()
            val msg = "Unexpected OAuth redirect URI."
            _uiState.update { it.copy(isConnecting = false, errorMessage = msg) }
            return OAuthCallbackOutcome.Failed(msg)
        }

        val params = parseQueryParameters(actualUri.rawQuery)
        val error = params["error"]
        if (!error.isNullOrBlank()) {
            clearPendingAuth()
            val outcome = if (error == "access_denied") {
                val msg = "Microsoft account linking was cancelled."
                _uiState.update { it.copy(isConnecting = false, errorMessage = msg) }
                OAuthCallbackOutcome.Cancelled(msg)
            } else {
                val msg = "Microsoft authorization failed. Please try again."
                _uiState.update { it.copy(isConnecting = false, errorMessage = msg) }
                OAuthCallbackOutcome.Failed(msg)
            }
            return outcome
        }

        val code = params["code"]?.trim()
        val returnedState = params["state"]?.trim()
        val expected = pendingState

        // Consume pendingState immediately to prevent duplicate/replay callbacks.
        pendingState = null

        if (expected.isNullOrBlank() || returnedState.isNullOrBlank() || !constantTimeEquals(expected, returnedState)) {
            val msg = "Invalid or expired OAuth state. Please try linking again."
            _uiState.update { it.copy(isConnecting = false, errorMessage = msg) }
            return OAuthCallbackOutcome.Failed(msg)
        }

        if (code.isNullOrBlank()) {
            val msg = "Missing authorization code from Microsoft callback."
            _uiState.update { it.copy(isConnecting = false, errorMessage = msg) }
            return OAuthCallbackOutcome.Failed(msg)
        }

        callbackInFlight = true
        return try {
            val linked = apiClient.completeMicrosoftCallback(code = code, state = returnedState)
            val refreshed = runCatching { apiClient.listConnectedAccounts() }.getOrElse { current ->
                _uiState.value.accounts + linked
            }
            _uiState.update {
                it.copy(
                    accounts = refreshed,
                    isConnecting = false,
                    errorMessage = null,
                    statusMessage = linked.providerEmail?.let { email ->
                        "Connected Microsoft account ($email)."
                    } ?: "Microsoft account connected.",
                )
            }
            OAuthCallbackOutcome.Linked(linked)
        } catch (e: OAuthApiException) {
            _uiState.update { it.copy(isConnecting = false, errorMessage = e.message) }
            OAuthCallbackOutcome.Failed(e.message)
        } finally {
            callbackInFlight = false
        }
    }

    /**
     * Called when the user closes the system browser without completing Microsoft sign-in.
     */
    fun handleBrowserCancelled() {
        if (pendingState != null && !callbackInFlight) {
            clearPendingAuth()
            _uiState.update {
                it.copy(
                    isConnecting = false,
                    errorMessage = "Microsoft sign-in was cancelled before completion.",
                )
            }
        }
    }

    suspend fun disconnectAccount(accountId: String) {
        if (_uiState.value.disconnectingAccountId != null) return
        _uiState.update {
            it.copy(disconnectingAccountId = accountId, errorMessage = null, statusMessage = null)
        }
        try {
            apiClient.disconnectAccount(accountId)
            val remaining = _uiState.value.accounts.filterNot { it.id == accountId }
            _uiState.update {
                it.copy(
                    accounts = remaining,
                    disconnectingAccountId = null,
                    statusMessage = "Microsoft account disconnected from Infora.",
                )
            }
        } catch (e: OAuthApiException) {
            _uiState.update { it.copy(disconnectingAccountId = null, errorMessage = e.message) }
        }
    }

    private fun clearPendingAuth() {
        pendingState = null
    }

    private fun matchesRedirectBase(expected: URI, actual: URI): Boolean {
        return expected.scheme.equals(actual.scheme, ignoreCase = true) &&
            (expected.host ?: "").equals(actual.host ?: "", ignoreCase = true) &&
            (expected.path ?: "") == (actual.path ?: "")
    }

    private fun constantTimeEquals(a: String, b: String): Boolean {
        return MessageDigest.isEqual(
            a.toByteArray(StandardCharsets.UTF_8),
            b.toByteArray(StandardCharsets.UTF_8),
        )
    }

    private fun parseQueryParameters(rawQuery: String?): Map<String, String> {
        if (rawQuery.isNullOrBlank()) return emptyMap()
        val result = LinkedHashMap<String, String>()
        for (pair in rawQuery.split("&")) {
            val idx = pair.indexOf('=')
            if (idx <= 0) continue
            val key = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8.name())
            val value = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8.name())
            result[key] = value
        }
        return result
    }
}
