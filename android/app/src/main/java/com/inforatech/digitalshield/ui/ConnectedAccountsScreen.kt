package com.inforatech.digitalshield.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.inforatech.digitalshield.oauth.ConnectedAccount
import com.inforatech.digitalshield.oauth.ConnectedAccountsUiState

@Composable
fun ConnectedAccountsScreen(
    state: ConnectedAccountsUiState,
    onConnectMicrosoft: () -> Unit,
    onDisconnectAccount: (String) -> Unit,
    onRefresh: () -> Unit,
) {
    var pendingDisconnect by remember { mutableStateOf<ConnectedAccount?>(null) }
    val microsoftAccounts = state.accounts.filter { it.provider == "microsoft" }

    Scaffold { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text("Connected Accounts", style = MaterialTheme.typography.headlineSmall)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Link your personal Microsoft account using the system browser. " +
                        "Personal Microsoft OAuth verifies identity and email only; it does not " +
                        "expose private sign-in history, active devices, or MFA status.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            state.statusMessage?.let { msg ->
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            msg,
                            modifier = Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.primary,
                        )
                    }
                }
            }

            state.errorMessage?.let { err ->
                item {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                err,
                                modifier = Modifier.weight(1f),
                                color = MaterialTheme.colorScheme.error,
                            )
                            TextButton(onClick = onRefresh) { Text("Retry") }
                        }
                    }
                }
            }

            item {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text("Microsoft (Personal)", style = MaterialTheme.typography.titleMedium)
                            Text(
                                "Links verified identity (openid, profile, email, User.Read).",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                        Button(
                            onClick = onConnectMicrosoft,
                            enabled = !state.isConnecting && !state.isLoading,
                        ) {
                            Text(if (state.isConnecting) "Opening…" else "Connect Microsoft")
                        }
                    }
                }
            }

            if (state.isLoading) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                }
            } else if (microsoftAccounts.isEmpty()) {
                item {
                    Text(
                        "No Microsoft accounts connected yet.",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            } else {
                items(microsoftAccounts, key = { it.id }) { account ->
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    account.displayName ?: account.providerEmail ?: "Microsoft Account",
                                    style = MaterialTheme.typography.titleSmall,
                                )
                                account.providerEmail?.let {
                                    Text(it, style = MaterialTheme.typography.bodySmall)
                                }
                                Text(
                                    "Status: ${account.status}",
                                    style = MaterialTheme.typography.labelSmall,
                                )
                            }
                            OutlinedButton(
                                onClick = { pendingDisconnect = account },
                                enabled = state.disconnectingAccountId == null,
                            ) {
                                Text(
                                    if (state.disconnectingAccountId == account.id) {
                                        "Disconnecting…"
                                    } else {
                                        "Disconnect"
                                    }
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    pendingDisconnect?.let { account ->
        AlertDialog(
            onDismissRequest = { pendingDisconnect = null },
            title = { Text("Disconnect Microsoft Account?") },
            text = {
                Text(
                    "This will unlink ${account.providerEmail ?: account.displayName ?: "this account"} " +
                        "from Infora Digital Shield and delete its stored credentials on the server."
                )
            },
            confirmButton = {
                Button(onClick = {
                    pendingDisconnect = null
                    onDisconnectAccount(account.id)
                }) {
                    Text("Disconnect")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDisconnect = null }) { Text("Cancel") }
            },
        )
    }
}
