package com.inforatech.digitalshield.oauth

import com.inforatech.digitalshield.auth.InforaTokenStore
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

private class InMemoryTokenStore(
    private var token: String? = "infora-jwt-123",
) : InforaTokenStore {
    override fun getAccessToken(): String? = token
    override fun saveAccessToken(token: String) {
        this.token = token
    }

    override fun clear() {
        token = null
    }
}

class MicrosoftOAuthManagerTest {
    private lateinit var server: MockWebServer
    private lateinit var tokenStore: InMemoryTokenStore
    private lateinit var apiClient: InforaOAuthApiClient
    private lateinit var manager: MicrosoftOAuthManager

    private val redirectUri = "com.inforatech.digitalshield://oauth/microsoft/callback"

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()

        tokenStore = InMemoryTokenStore()
        apiClient = InforaOAuthApiClient(
            baseUrl = server.url("/api/v1").toString(),
            tokenStore = tokenStore,
        )
        manager = MicrosoftOAuthManager(
            apiClient = apiClient,
            expectedRedirectUri = redirectUri,
        )
    }

    @After
    fun tearDown() {
        server.shutdown()
    }

    @Test
    fun `startMicrosoftAuthorization sends platform android and validates PKCE S256`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?client_id=ms-mob-1&redirect_uri=com.inforatech.digitalshield%3A%2F%2Foauth%2Fmicrosoft%2Fcallback" +
                "&response_type=code&code_challenge=abc123&code_challenge_method=S256&state=state-xyz-123456"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )

        val returnedUrl = manager.startMicrosoftAuthorization()
        assertEquals(authUrl, returnedUrl)
        assertTrue(manager.hasPendingAuthorization)

        val recorded = server.takeRequest()
        assertEquals("/api/v1/oauth/microsoft/authorize", recorded.path)
        assertEquals("Bearer infora-jwt-123", recorded.getHeader("Authorization"))
        val reqJson = JsonUtil.parseObject(recorded.body.readUtf8())
        assertEquals("android", reqJson["platform"])
    }

    @Test
    fun `successful callback links multiple accounts and stores no Microsoft tokens locally`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?client_id=ms-mob-1&code_challenge=abc&code_challenge_method=S256&state=state-ok-12345678"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """
                    {
                      "id": "acc-ms-2",
                      "provider": "microsoft",
                      "provider_email": "two@outlook.com",
                      "provider_email_verified": true,
                      "display_name": "Two Outlook",
                      "scopes": ["openid", "profile", "email", "User.Read"],
                      "status": "active",
                      "created_at": "2026-11-26T12:00:00"
                    }
                    """.trimIndent(),
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """
                    [
                      {"id":"acc-ms-1","provider":"microsoft","provider_email":"one@outlook.com","provider_email_verified":true,"display_name":"One","scopes":["openid"],"status":"active","created_at":"2026-11-26T11:00:00"},
                      {"id":"acc-ms-2","provider":"microsoft","provider_email":"two@outlook.com","provider_email_verified":true,"display_name":"Two Outlook","scopes":["openid","profile","email","User.Read"],"status":"active","created_at":"2026-11-26T12:00:00"}
                    ]
                    """.trimIndent(),
                ),
        )

        assertNotNull(manager.startMicrosoftAuthorization())
        val outcome = manager.handleCallbackUri("$redirectUri?code=auth-code-999&state=state-ok-12345678")
        assertTrue(outcome is OAuthCallbackOutcome.Linked)
        assertFalse(manager.hasPendingAuthorization)
        assertEquals(2, manager.uiState.value.accounts.size)
        assertEquals("infora-jwt-123", tokenStore.getAccessToken())

        server.takeRequest() // authorize
        val cbReq = server.takeRequest()
        assertEquals("/api/v1/oauth/microsoft/callback", cbReq.path)
        val cbJson = JsonUtil.parseObject(cbReq.body.readUtf8())
        assertEquals("auth-code-999", cbJson["code"])
        assertEquals("state-ok-12345678", cbJson["state"])
        assertEquals("android", cbJson["platform"])
    }

    @Test
    fun `cancellation via access_denied or browser close clears state and skips callback`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?code_challenge=abc&code_challenge_method=S256&state=state-cancel-123"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )

        assertNotNull(manager.startMicrosoftAuthorization())
        val outcome = manager.handleCallbackUri("$redirectUri?error=access_denied")
        assertTrue(outcome is OAuthCallbackOutcome.Cancelled)
        assertFalse(manager.hasPendingAuthorization)
        assertEquals(1, server.requestCount) // only /authorize, never /callback

        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )
        assertNotNull(manager.startMicrosoftAuthorization())
        manager.handleBrowserCancelled()
        assertFalse(manager.hasPendingAuthorization)
        assertFalse(manager.uiState.value.isConnecting)
    }

    @Test
    fun `invalid state and duplicate callback are rejected without calling backend`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?code_challenge=abc&code_challenge_method=S256&state=expected-state-12345"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )

        assertNotNull(manager.startMicrosoftAuthorization())
        val mismatch = manager.handleCallbackUri("$redirectUri?code=c1&state=wrong-state-99999")
        assertTrue(mismatch is OAuthCallbackOutcome.Failed)
        assertFalse(manager.hasPendingAuthorization)
        assertEquals(1, server.requestCount) // never called /callback

        val replay = manager.handleCallbackUri("$redirectUri?code=c1&state=expected-state-12345")
        assertTrue(replay is OAuthCallbackOutcome.Failed)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `backend 409 conflict surfaces safe error and disconnect removes account`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?code_challenge=abc&code_challenge_method=S256&state=state-conflict-123"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(409)
                .setBody("""{"detail":"This external account cannot be linked"}"""),
        )

        assertNotNull(manager.startMicrosoftAuthorization())
        val outcome = manager.handleCallbackUri("$redirectUri?code=c1&state=state-conflict-123")
        assertTrue(outcome is OAuthCallbackOutcome.Failed)
        assertTrue(manager.uiState.value.errorMessage?.contains("already linked") == true)

        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """[{"id":"acc-1","provider":"microsoft","provider_email":"one@outlook.com","provider_email_verified":true,"display_name":"One","scopes":["openid"],"status":"active","created_at":"2026-11-26T11:00:00"}]""",
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """{"message":"Connected account disconnected","disconnected_account_id":"acc-1","upstream_revocation_status":"unsupported"}""",
                ),
        )
        manager.loadAccounts()
        assertEquals(1, manager.uiState.value.accounts.size)

        manager.disconnectAccount("acc-1")
        assertEquals(0, manager.uiState.value.accounts.size)
        assertNull(manager.uiState.value.errorMessage)
    }

    @Test
    fun `process recreation restores pending state once and prevents replay`() = runBlocking {
        val authUrl =
            "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" +
                "?code_challenge=abc&code_challenge_method=S256&state=state-recreated-123"
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JsonUtil.objectJson(
                        "provider" to "microsoft",
                        "platform" to "android",
                        "authorization_url" to authUrl,
                        "expires_at" to "2026-11-26T23:59:00",
                    ),
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """{"id":"acc-r1","provider":"microsoft","provider_email":"rec@outlook.com","provider_email_verified":true,"display_name":"Rec","scopes":["openid"],"status":"active","created_at":"2026-11-26T12:00:00"}""",
                ),
        )
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    """[{"id":"acc-r1","provider":"microsoft","provider_email":"rec@outlook.com","provider_email_verified":true,"display_name":"Rec","scopes":["openid"],"status":"active","created_at":"2026-11-26T12:00:00"}]""",
                ),
        )

        assertNotNull(manager.startMicrosoftAuthorization())
        val savedState = manager.exportPendingState()
        assertNotNull(savedState)

        val recreatedManager = MicrosoftOAuthManager(apiClient = apiClient, expectedRedirectUri = redirectUri)
        recreatedManager.restorePendingState(savedState)
        assertTrue(recreatedManager.hasPendingAuthorization)

        val outcome = recreatedManager.handleCallbackUri("$redirectUri?code=code-rec&state=state-recreated-123")
        assertTrue(outcome is OAuthCallbackOutcome.Linked)
        assertFalse(recreatedManager.hasPendingAuthorization)

        val replay = recreatedManager.handleCallbackUri("$redirectUri?code=code-rec&state=state-recreated-123")
        assertTrue(replay is OAuthCallbackOutcome.Failed)
    }
}
