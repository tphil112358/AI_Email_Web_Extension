// AI Provider configurations
const AI_PROVIDERS = {
    ollama: {
        name: "Ollama",
        requiresApiKey: false,
        endpoint: "http://localhost:11434/api/generate",
        chatEndpoint: "http://localhost:11434/api/chat",
        defaultModel: "llama3.1",
        testEndpoint: "http://localhost:11434/api/tags"
    },
    groq: {
        name: "Groq",
        requiresApiKey: true,
        endpoint: "https://api.groq.com/openai/v1/chat/completions",
        defaultModel: "llama-3.1-8b-instant",
        testEndpoint: "https://api.groq.com/openai/v1/models"
    },
    together: {
        name: "Together.ai",
        requiresApiKey: true,
        endpoint: "https://api.together.xyz/v1/chat/completions",
        defaultModel: "meta-llama/Llama-3-8b-chat-hf",
        testEndpoint: "https://api.together.xyz/v1/models"
    },
    openai: {
        name: "OpenAI",
        requiresApiKey: true,
        endpoint: "https://api.openai.com/v1/chat/completions",
        defaultModel: "gpt-3.5-turbo",
        testEndpoint: "https://api.openai.com/v1/models"
    },
    anthropic: {
        name: "Anthropic",
        requiresApiKey: true,
        endpoint: "https://api.anthropic.com/v1/messages",
        defaultModel: "claude-3-haiku-20240307",
        testEndpoint: "https://api.anthropic.com/v1/models"
    }
};

// DOM elements
const providerSelect = document.getElementById("aiProvider");
const apiKeyInput = document.getElementById("apiKey");
const apiKeyGroup = document.getElementById("apiKeyGroup");
const saveBtn = document.getElementById("saveBtn");
const cancelBtn = document.getElementById("cancelBtn");
const testConnectionBtn = document.getElementById("testConnection");
const statusMessage = document.getElementById("statusMessage");

// Load saved settings on page load
document.addEventListener("DOMContentLoaded", loadSettings);

// Provider selection change handler
providerSelect.addEventListener("change", () => {
    const provider = providerSelect.value;
    updateProviderUI(provider);
});

// Save button handler
saveBtn.addEventListener("click", saveSettings);

// Cancel button handler
cancelBtn.addEventListener("click", () => {
    window.close();
});

// Test connection button handler
testConnectionBtn.addEventListener("click", testConnection);

// Update UI based on selected provider
function updateProviderUI(provider) {
    const config = AI_PROVIDERS[provider];
    
    // Show/hide API key field
    if (config.requiresApiKey) {
        apiKeyGroup.style.display = "block";
    } else {
        apiKeyGroup.style.display = "none";
    }
    
    // Show appropriate info box
    document.querySelectorAll(".provider-info").forEach(info => {
        info.classList.add("hidden");
    });
    document.getElementById(`info-${provider}`).classList.remove("hidden");
}

// Load settings from storage
async function loadSettings() {
    try {
        const result = await chrome.storage.sync.get(["aiProvider", "apiKey"]);
        
        if (result.aiProvider) {
            providerSelect.value = result.aiProvider;
        }
        
        if (result.apiKey) {
            apiKeyInput.value = result.apiKey;
        }
        
        // Update UI for current provider
        updateProviderUI(providerSelect.value);
    } catch (error) {
        console.error("Error loading settings:", error);
        showStatus("Error loading settings", "error");
    }
}

// Save settings to storage
async function saveSettings() {
    const provider = providerSelect.value;
    const apiKey = apiKeyInput.value.trim();
    const config = AI_PROVIDERS[provider];
    
    // Validate API key if required
    if (config.requiresApiKey && !apiKey) {
        showStatus("API key is required for " + config.name, "error");
        return;
    }
    
    try {
        await chrome.storage.sync.set({
            aiProvider: provider,
            apiKey: apiKey
        });
        
        showStatus("Settings saved successfully! ✓", "success");
        
        // Close window after short delay
        setTimeout(() => {
            window.close();
        }, 1500);
    } catch (error) {
        console.error("Error saving settings:", error);
        showStatus("Error saving settings", "error");
    }
}

// Test connection to selected provider
async function testConnection() {
    const provider = providerSelect.value;
    const apiKey = apiKeyInput.value.trim();
    const config = AI_PROVIDERS[provider];
    
    testConnectionBtn.disabled = true;
    testConnectionBtn.textContent = "Testing...";
    
    try {
        if (provider === "ollama") {
            // Test Ollama by checking if it's running
            const response = await fetch(config.testEndpoint);
            if (response.ok) {
                showStatus("✓ Ollama is running and accessible", "success");
            } else {
                showStatus("✗ Ollama is not responding. Make sure it's installed and running.", "error");
            }
        } else {
            // Test API providers
            if (!apiKey) {
                showStatus("Please enter an API key to test", "error");
                return;
            }
            
            const headers = {
                "Content-Type": "application/json"
            };
            
            // Add auth header based on provider
            if (provider === "anthropic") {
                headers["x-api-key"] = apiKey;
                headers["anthropic-version"] = "2023-06-01";
            } else {
                headers["Authorization"] = `Bearer ${apiKey}`;
            }
            
            const response = await fetch(config.testEndpoint, { 
                method: "GET",
                headers 
            });
            
            if (response.ok) {
                showStatus(`✓ ${config.name} API key is valid`, "success");
            } else {
                const errorText = await response.text();
                showStatus(`✗ ${config.name} API key is invalid (${response.status})`, "error");
            }
        }
    } catch (error) {
        console.error("Connection test failed:", error);
        if (provider === "ollama") {
            showStatus("✗ Cannot connect to Ollama. Is it installed and running?", "error");
        } else {
            showStatus(`✗ Connection failed: ${error.message}`, "error");
        }
    } finally {
        testConnectionBtn.disabled = false;
        testConnectionBtn.textContent = "Test Connection";
    }
}

// Show status message
function showStatus(message, type) {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type} visible`;
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        statusMessage.classList.remove("visible");
    }, 5000);
}

// Export provider config for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { AI_PROVIDERS };
}
