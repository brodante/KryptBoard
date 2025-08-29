package com.example.secureime.ime

import android.inputmethodservice.InputMethodService
import android.view.View
import androidx.compose.ui.platform.ComposeView
import com.example.secureime.ui.KeyboardRoot

class SecureKeyboardService : InputMethodService() {

    override fun onCreateInputView(): View {
        return ComposeView(this).apply {
            setContent {
                KeyboardRoot(
                    onCommit = { text ->
                        currentInputConnection?.commitText(text, 1)
                    },
                    onEnter = {
                        // Fallback: try action, else newline
                        val ic = currentInputConnection
                        val handled = ic?.performEditorAction(android.view.inputmethod.EditorInfo.IME_ACTION_DONE) == true
                        if (!handled) {
                            ic?.commitText("\n", 1)
                        }
                    }
                )
            }
        }
    }
}
