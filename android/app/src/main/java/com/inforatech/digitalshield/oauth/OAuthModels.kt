package com.inforatech.digitalshield.oauth

data class OAuthAuthorizeResponse(
    val provider: String,
    val platform: String,
    val authorizationUrl: String,
    val expiresAt: String,
)

data class ConnectedAccount(
    val id: String,
    val provider: String,
    val providerEmail: String?,
    val providerEmailVerified: Boolean,
    val displayName: String?,
    val scopes: List<String>,
    val status: String,
    val createdAt: String,
)

data class DisconnectAccountResponse(
    val message: String,
    val disconnectedAccountId: String,
    val upstreamRevocationStatus: String,
)

class OAuthApiException(
    val statusCode: Int,
    override val message: String,
) : Exception(message)

sealed interface OAuthCallbackOutcome {
    data class Linked(val account: ConnectedAccount) : OAuthCallbackOutcome
    data class Cancelled(val reason: String) : OAuthCallbackOutcome
    data class Failed(val message: String) : OAuthCallbackOutcome
}
