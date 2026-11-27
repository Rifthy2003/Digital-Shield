package com.inforatech.digitalshield.auth

/**
 * Stores ONLY Infora's own session JWTs.
 * Microsoft OAuth access and refresh tokens are NEVER stored on Android.
 */
interface InforaTokenStore {
    fun getAccessToken(): String?
    fun saveAccessToken(token: String)
    fun clear()
}
