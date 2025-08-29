package com.example.secureime.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.cryptolib.ChaCha20Poly1305Stub
import com.example.cryptolib.Envelope

@Composable
fun KeyboardRoot(
    onCommit: (String) -> Unit,
    onEnter: () -> Unit
) {
    var isEncrypted by remember { mutableStateOf(false) }
    var bufferedText by remember { mutableStateOf("") }
    val cipher = remember { ChaCha20Poly1305Stub() }

    MaterialTheme {
        Surface(
            modifier = Modifier.fillMaxWidth(),
            color = MaterialTheme.colorScheme.surface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Top section with text field and controls
                Card(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp)
                    ) {
                        // Plaintext display field
                        OutlinedTextField(
                            value = bufferedText,
                            onValueChange = { bufferedText = it },
                            label = { Text("Text Buffer") },
                            modifier = Modifier.fillMaxWidth(),
                            readOnly = true
                        )

                        Spacer(modifier = Modifier.height(8.dp))

                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            // Plain/Encrypted toggle
                            Row(
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Switch(
                                    checked = isEncrypted,
                                    onCheckedChange = { isEncrypted = it }
                                )
                                Spacer(modifier = Modifier.width(8.dp))
                                Text(
                                    text = if (isEncrypted) "Encrypted" else "Plain",
                                    fontWeight = FontWeight.Medium
                                )
                            }

                            // Encrypt & Send button (only visible in encrypted mode)
                            if (isEncrypted) {
                                Button(
                                    onClick = {
                                        if (bufferedText.isNotEmpty()) {
                                            try {
                                                val cipherOut = cipher.encrypt(bufferedText.toByteArray())
                                                val envelope = Envelope.toString(cipherOut)
                                                onCommit(envelope)
                                                bufferedText = ""
                                            } catch (e: Exception) {
                                                // Fallback to plain text if encryption fails
                                                onCommit(bufferedText)
                                                bufferedText = ""
                                            }
                                        }
                                    },
                                    enabled = bufferedText.isNotEmpty()
                                ) {
                                    Text("Encrypt & Send")
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Keyboard section
                Card(
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text(
                            text = "Keyboard",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Medium
                        )

                        Spacer(modifier = Modifier.height(12.dp))

                        // First row: A, B
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            KeyButton(
                                text = "A",
                                onClick = {
                                    if (isEncrypted) {
                                        bufferedText += "A"
                                    } else {
                                        onCommit("A")
                                    }
                                }
                            )
                            KeyButton(
                                text = "B",
                                onClick = {
                                    if (isEncrypted) {
                                        bufferedText += "B"
                                    } else {
                                        onCommit("B")
                                    }
                                }
                            )
                        }

                        Spacer(modifier = Modifier.height(8.dp))

                        // Second row: Space, Enter
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            KeyButton(
                                text = "Space",
                                onClick = {
                                    if (isEncrypted) {
                                        bufferedText += " "
                                    } else {
                                        onCommit(" ")
                                    }
                                }
                            )
                            KeyButton(
                                text = "Enter",
                                onClick = {
                                    if (isEncrypted) {
                                        bufferedText += "\n"
                                    } else {
                                        onEnter()
                                    }
                                }
                            )
                        }
                    }
                }
            }
        }
    }
}
