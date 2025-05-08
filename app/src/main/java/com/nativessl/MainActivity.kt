package com.nativessl

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.nativessl.databinding.ActivityMainBinding
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    external fun nativeVerifyServer(domain: String, port: Int): String

    companion object {
        init {
            System.loadLibrary("native-lib")
        }

        private const val DEFAULT_DOMAIN = "mobilehack.ing"
        private const val DEFAULT_PORT = 1337
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Setup ViewBinding
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.btnCheck.setOnClickListener {
            performSslCheck(DEFAULT_DOMAIN, DEFAULT_PORT)
        }
    }

    private fun performSslCheck(domain: String, port: Int) {
        binding.txtResult.text = getString(R.string.checking)

        CoroutineScope(Dispatchers.IO).launch {
            val result = try {
                nativeVerifyServer(domain, port)
            } catch (e: Exception) {
                "Error: ${e.message}"
            }

            withContext(Dispatchers.Main) {
                binding.txtResult.text = result
            }
        }
    }
}