package com.inforatech.digitalshield.oauth

import com.inforatech.digitalshield.auth.InforaTokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

interface OAuthBackendClient {
    suspend fun authorizeMicrosoft(): OAuthAuthorizeResponse
    suspend fun completeMicrosoftCallback(code: String, state: String): ConnectedAccount
    suspend fun listConnectedAccounts(): List<ConnectedAccount>
    suspend fun disconnectAccount(accountId: String): DisconnectAccountResponse
}

class InforaOAuthApiClient(
    private val baseUrl: String,
    private val tokenStore: InforaTokenStore,
) : OAuthBackendClient {

    private val trimmedBase = baseUrl.trimEnd('/')

    private fun requireBearerToken(): String {
        val token = tokenStore.getAccessToken()?.trim()
        if (token.isNullOrEmpty()) {
            throw OAuthApiException(401, "Please sign in to Infora before linking Microsoft.")
        }
        return token
    }

    override suspend fun authorizeMicrosoft(): OAuthAuthorizeResponse = withContext(Dispatchers.IO) {
        val jwt = requireBearerToken()
        val payload = JsonUtil.objectJson("platform" to "android")
        executeJsonObject(
            url = "$trimmedBase/oauth/microsoft/authorize",
            method = "POST",
            bearerToken = jwt,
            jsonBody = payload,
        ) { json ->
            OAuthAuthorizeResponse(
                provider = json["provider"] as String,
                platform = (json["platform"] as? String) ?: "android",
                authorizationUrl = json["authorization_url"] as String,
                expiresAt = json["expires_at"] as String,
            )
        }
    }

    override suspend fun completeMicrosoftCallback(code: String, state: String): ConnectedAccount =
        withContext(Dispatchers.IO) {
            val jwt = requireBearerToken()
            val payload = JsonUtil.objectJson(
                "code" to code,
                "state" to state,
                "platform" to "android",
            )
            executeJsonObject(
                url = "$trimmedBase/oauth/microsoft/callback",
                method = "POST",
                bearerToken = jwt,
                jsonBody = payload,
            ) { parseConnectedAccount(it) }
        }

    @Suppress("UNCHECKED_CAST")
    override suspend fun listConnectedAccounts(): List<ConnectedAccount> = withContext(Dispatchers.IO) {
        val jwt = requireBearerToken()
        executeRaw(
            url = "$trimmedBase/oauth/accounts",
            method = "GET",
            bearerToken = jwt,
            jsonBody = null,
        ) { raw ->
            JsonUtil.parseArray(raw).map { item ->
                parseConnectedAccount(item as Map<String, Any?>)
            }
        }
    }

    override suspend fun disconnectAccount(accountId: String): DisconnectAccountResponse =
        withContext(Dispatchers.IO) {
            val jwt = requireBearerToken()
            executeJsonObject(
                url = "$trimmedBase/oauth/accounts/$accountId",
                method = "DELETE",
                bearerToken = jwt,
                jsonBody = null,
            ) { json ->
                DisconnectAccountResponse(
                    message = json["message"] as String,
                    disconnectedAccountId = json["disconnected_account_id"] as String,
                    upstreamRevocationStatus = json["upstream_revocation_status"] as String,
                )
            }
        }

    private inline fun <T> executeJsonObject(
        url: String,
        method: String,
        bearerToken: String,
        jsonBody: String?,
        parser: (Map<String, Any?>) -> T,
    ): T {
        return executeRaw(url, method, bearerToken, jsonBody) { raw -> parser(JsonUtil.parseObject(raw)) }
    }

    private inline fun <T> executeRaw(
        url: String,
        method: String,
        bearerToken: String,
        jsonBody: String?,
        parser: (String) -> T,
    ): T {
        val conn = (URL(url).openConnection() as HttpURLConnection)
        try {
            conn.requestMethod = method
            conn.connectTimeout = 15_000
            conn.readTimeout = 15_000
            conn.setRequestProperty("Authorization", "Bearer $bearerToken")
            conn.setRequestProperty("Accept", "application/json")
            if (jsonBody != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json; charset=utf-8")
                conn.outputStream.use { os ->
                    os.write(jsonBody.toByteArray(Charsets.UTF_8))
                }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val rawBody = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            if (code !in 200..299) {
                val detail = runCatching { JsonUtil.parseObject(rawBody)["detail"] as? String ?: "" }.getOrDefault("")
                val safeMessage = when (code) {
                    401 -> "Your Infora session has expired. Please sign in again."
                    409 -> "This Microsoft account is already linked to another Infora user."
                    429 -> "Too many requests. Please wait a moment and try again."
                    503 -> "Microsoft linking is not configured on this server."
                    else -> detail.ifBlank { "Request failed ($code)." }
                }
                throw OAuthApiException(code, safeMessage)
            }
            return parser(rawBody)
        } catch (e: OAuthApiException) {
            throw e
        } catch (_: IOException) {
            throw OAuthApiException(0, "Network error while contacting Infora server.")
        } finally {
            conn.disconnect()
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun parseConnectedAccount(json: Map<String, Any?>): ConnectedAccount {
        val scopesRaw = (json["scopes"] as? List<Any?>).orEmpty()
        val scopes = scopesRaw.mapNotNull { it as? String }
        return ConnectedAccount(
            id = json["id"] as String,
            provider = json["provider"] as String,
            providerEmail = json["provider_email"] as? String,
            providerEmailVerified = (json["provider_email_verified"] as? Boolean) ?: false,
            displayName = json["display_name"] as? String,
            scopes = scopes,
            status = (json["status"] as? String) ?: "active",
            createdAt = (json["created_at"] as? String) ?: "",
        )
    }
}
