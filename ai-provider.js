// AI Provider Helper Module
// This module provides a unified interface for interacting with different AI providers

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

/**
 * Get the current AI provider settings
 * @returns {Promise<{provider: string, apiKey: string, config: object}>}
 */
async function getProviderSettings() {
    try {
        const result = await chrome.storage.sync.get(["aiProvider", "apiKey"]);
        const provider = result.aiProvider || "ollama"; // Default to Ollama
        const apiKey = result.apiKey || "";
        const config = AI_PROVIDERS[provider];
        
        return { provider, apiKey, config };
    } catch (error) {
        console.error("Error getting provider settings:", error);
        // Return default (Ollama) on error
        return { 
            provider: "ollama", 
            apiKey: "", 
            config: AI_PROVIDERS.ollama 
        };
    }
}

/**
 * Check if a provider is configured and ready to use
 * @returns {Promise<{ready: boolean, reason: string}>}
 */
async function checkProviderReady() {
    const { provider, apiKey, config } = await getProviderSettings();
    
    // Check if API key is required but missing
    if (config.requiresApiKey && !apiKey) {
        return { 
            ready: false, 
            reason: `${config.name} requires an API key. Please configure it in Settings.`,
            needsSetup: true
        };
    }
    
    // For Ollama, we can do a quick availability check
    if (provider === "ollama") {
        try {
            const response = await fetch(config.testEndpoint, { 
                method: "GET",
                signal: AbortSignal.timeout(2000) // 2 second timeout
            });
            
            if (response.ok) {
                return { ready: true, reason: "Ollama is running" };
            } else {
                return { 
                    ready: false, 
                    reason: "Ollama is not responding. Make sure it's installed and running.",
                    needsSetup: true
                };
            }
        } catch (error) {
            return { 
                ready: false, 
                reason: "Cannot connect to Ollama. Is it running?",
                needsSetup: true
            };
        }
    }
    
    // For API providers, assume ready if API key is present
    return { ready: true, reason: `${config.name} is configured` };
}

/**
 * Send a prompt to the configured AI provider
 * @param {string} prompt - The prompt to send
 * @param {boolean} stream - Whether to stream the response (for Ollama)
 * @returns {Promise<string>} - The AI response
 */
async function sendPrompt(prompt, stream = false) {
    const { provider, apiKey, config } = await getProviderSettings();
    
    if (provider === "ollama") {
        return sendOllamaPrompt(prompt, config, stream);
    } else if (provider === "anthropic") {
        return sendAnthropicPrompt(prompt, config, apiKey);
    } else {
        // OpenAI-compatible providers (Groq, Together, OpenAI)
        return sendOpenAICompatiblePrompt(prompt, config, apiKey);
    }
}

/**
 * Send prompt to Ollama
 */
async function sendOllamaPrompt(prompt, config, stream = false) {
    const payload = {
        model: config.defaultModel,
        prompt: prompt,
        stream: stream
    };
    
    const response = await fetch(config.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
        throw new Error(`Ollama request failed: ${response.status}`);
    }
    
    if (stream) {
        return response; // Return response for streaming handling
    }
    
    const data = await response.json();
    return data.response || "";
}

/**
 * Send prompt to OpenAI-compatible providers (Groq, Together, OpenAI)
 */
async function sendOpenAICompatiblePrompt(prompt, config, apiKey) {
    const payload = {
        model: config.defaultModel,
        messages: [
            { role: "user", content: prompt }
        ],
        temperature: 0.7,
        max_tokens: 500
    };
    
    const response = await fetch(config.endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${config.name} request failed (${response.status}): ${errorText}`);
    }
    
    const data = await response.json();
    return data.choices[0].message.content;
}

/**
 * Send prompt to Anthropic (Claude)
 */
async function sendAnthropicPrompt(prompt, config, apiKey) {
    const payload = {
        model: config.defaultModel,
        messages: [
            { role: "user", content: prompt }
        ],
        max_tokens: 500
    };
    
    const response = await fetch(config.endpoint, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "x-api-key": apiKey,
            "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify(payload)
    });
    
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Anthropic request failed (${response.status}): ${errorText}`);
    }
    
    const data = await response.json();
    return data.content[0].text;
}

// Export for use in other scripts
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { 
        AI_PROVIDERS, 
        getProviderSettings, 
        checkProviderReady, 
        sendPrompt 
    };
}
