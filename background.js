// Import AI provider helpers (loaded via manifest)
importScripts('ai-provider.js', 'prompt-templates.js');

chrome.runtime.onConnect.addListener((port) => {
  if (port.name === "ollamaStream") {
    port.onMessage.addListener(async (msg) => {
      if (msg.type === "SUMMARIZE_TEXT") {
        try {
          await handleSummarization(msg.text, port);
        } catch (err) {
          port.postMessage({ type: "ERROR", error: String(err) });
        }
      }
    });
  }
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "URL_CHANGED") {
    console.log("URL changed:", msg.url);
  }
  
  // Check if AI provider is configured and ready
  if (msg.type === "CHECK_PROVIDER") {
    checkProviderReady()
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ ready: false, reason: error.message, needsSetup: true }));
    return true; // Keep channel open for async response
  }
  
  // Handle direct summarization requests (non-streaming)
  if (msg.type === "SUMMARIZE_EMAIL") {
    handleDirectSummarization(msg.text)
      .then(result => sendResponse(result))
      .catch(error => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }

  // New: Summarize inbox request (triggered by popup)
  if (msg.type === "SUMMARIZE_INBOX_REQUEST") {
    handleSummarizeInboxRequest(msg, sender, sendResponse).catch(err => {
      console.error("SUMMARIZE_INBOX_REQUEST failed:", err);
      sendResponse({ success: false, error: String(err) });
    });
    return true; // Keep channel open for async response
  }

  // New: Scan inbox threats via AI (suspicious senders/subjects)
  if (msg.type === "SCAN_INBOX_THREATS") {
    (async () => {
      try {
        // Identify active Gmail tab (prefer tabId from popup)
        let tabId = msg && msg.tabId ? msg.tabId : await findActiveGmailTabId();
        if (!tabId) {
          sendResponse({ result: { level: "neutral", detail: "Open Gmail inbox to analyze" } });
          return;
        }

        const threads = await requestInboxThreads(tabId);
        if (!threads || !threads.length) {
          sendResponse({ result: { level: "neutral", detail: "No recent threads found to analyze" } });
          return;
        }

        const filtered = filterThreadsByDateAndLimit(threads);

        // Build a short data block for AI that lists sender+subject pairs
        const itemsText = filtered.map((t, i) => `Item ${i + 1}: Sender: "${t.sender || ''}" Subject: "${t.subject || ''}"`).join("\n");

        const SYSTEM = `You are a cybersecurity expert. Analyze the following recent email senders and subjects and identify any suspicious or likely malicious items. Look for typosquatting (e.g. 'rnicrosft' for 'microsoft'), odd domains in sender addresses, repeated misspellings, or clearly fraudulent subjects. Output JSON only with these fields:
{
  "threat_level": "safe" | "warning" | "danger",
  "confidence": 0.0 to 1.0,
  "suspicious_items": [
    {
      "index": number,
      "sender": "",
      "subject": "",
      "reason": "",
      "indicators": ["..."]
    }
  ],
  "overall_assessment": ""
}`;

        const prompt = `${SYSTEM}\n\nInbox items (last 7 days):\n${itemsText}\n\nOutput (JSON only):`;

        // Ask AI
        let llmResp = null;
        try {
          llmResp = await sendPrompt(prompt, false);
        } catch (aiErr) {
          console.warn("AI provider failed for inbox threats:", aiErr);
          llmResp = null;
        }

        // Try to parse AI response if present
        let parsed = null;
        if (typeof llmResp === "string" && llmResp.trim()) {
          parsed = parseAIResponse(llmResp);
        }

        // If AI parsing failed, fallback to local heuristic analysis
        if (!parsed || parsed.error) {
          console.warn("AI analysis failed or returned unexpected result. Falling back to local heuristics.");
          const fallback = analyzeInboxLocally(filtered);
          sendResponse({ result: fallback });
          return;
        }

        // Normalize parsed structure and respond
        try {
          const lvl = parsed.threat_level || parsed.threatLevel || parsed.level || "safe";
          const detail = parsed.overall_assessment || (parsed.suspicious_items && parsed.suspicious_items.length ? `Found ${parsed.suspicious_items.length} suspicious item(s)` : "Checks out! ✅");
          const items = parsed.suspicious_items || parsed.items || [];
          sendResponse({ result: { level: lvl === "danger" ? "danger" : lvl === "warning" ? "warning" : "safe", detail, findings: items } });
        } catch (e) {
          console.error("Formatting AI parsed response failed:", e);
          const fallback = analyzeInboxLocally(filtered);
          sendResponse({ result: fallback });
        }
      } catch (err) {
        console.error("SCAN_INBOX_THREATS failed:", err);
        sendResponse({ result: { level: "neutral", detail: "Inbox scan failed: " + String(err) } });
      }
    })();
    return true;
  }
});

/**
 * Local fallback analysis for inbox threads
 * Returns object: { level, detail, findings }
 */
function analyzeInboxLocally(threads) {
  // Known brand list to check for typosquatting
  const knownBrands = ["microsoft", "google", "amazon", "paypal", "apple", "facebook", "bank", "chase", "bankofamerica", "stripe", "github"];
  const suspiciousTLDs = [".tk", ".ru", ".ml", ".ga", ".cf", ".biz", ".info"];
  const findings = [];

  for (let i = 0; i < threads.length; i++) {
    const t = threads[i];
    const sender = (t.sender || "").toLowerCase();
    const subject = (t.subject || "").toLowerCase();

    // Extract domain if sender contains an email address
    let domain = "";
    try {
      const m = sender.match(/@([^\s>]+)/);
      if (m && m[1]) domain = m[1].toLowerCase();
    } catch {}

    // Heuristic 1: suspicious tld in domain
    if (domain) {
      for (const tld of suspiciousTLDs) {
        if (domain.endsWith(tld)) {
          findings.push({
            index: i,
            sender: t.sender,
            subject: t.subject,
            reason: `Sender domain uses suspicious TLD (${tld})`,
            indicators: ["suspicious-tld"]
          });
          break;
        }
      }
    }

    // Heuristic 2: typosquatting detection using simple Levenshtein
    const tokens = (sender + " " + subject).split(/[^a-z0-9]+/).filter(Boolean);
    for (const token of tokens) {
      for (const brand of knownBrands) {
        // Skip very short comparisons
        if (brand.length < 4 || token.length < 4) continue;
        const dist = levenshtein(token.replace(/[^a-z0-9]/g, ""), brand);
        // Accept small distance (1 or 2) as suspicious depending on length
        if (dist > 0 && dist <= Math.max(1, Math.floor(brand.length * 0.2))) {
          findings.push({
            index: i,
            sender: t.sender,
            subject: t.subject,
            reason: `Possible typosquatting: "${token}" ≈ "${brand}" (distance ${dist})`,
            indicators: ["typosquatting", `similar-to-${brand}`]
          });
        }
      }
    }
  }

  // Decide level
  if (findings.length === 0) {
    return { level: "safe", detail: "Checks out! ✅", findings: [] };
  }

  // If any suspicious-tld or typosquatting with small dist -> danger, else warning
  const strong = findings.some(f => f.indicators && f.indicators.includes("suspicious-tld") || (f.indicators && f.indicators.includes("typosquatting")));
  const level = strong ? "danger" : "warning";
  const detail = level === "danger" ? `🚨 ${findings.length} suspicious item(s) detected` : `⚠️ ${findings.length} potentially suspicious item(s) detected`;

  return { level, detail, findings };
}

/**
 * Simple Levenshtein distance
 */
function levenshtein(a, b) {
  if (!a || !b) return (a || b) ? Math.max(a.length, b.length) : 0;
  a = a.toLowerCase();
  b = b.toLowerCase();
  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Find active Gmail tab id (returns null if not found)
 */
async function findActiveGmailTabId() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs && tabs[0] && tabs[0].url && tabs[0].url.includes("mail.google.com")) {
      return tabs[0].id;
    }
    // Try to find any gmail tab in the window
    const allTabs = await chrome.tabs.query({ currentWindow: true });
    for (const t of allTabs) {
      if (t.url && t.url.includes("mail.google.com")) return t.id;
    }
    // Try globally
    const all = await chrome.tabs.query({});
    for (const t of all) {
      if (t.url && t.url.includes("mail.google.com")) return t.id;
    }
  } catch (e) {
    console.warn("findActiveGmailTabId error:", e);
  }
  return null;
}

/**
 * Handle inbox summarization orchestration
 * Accepts the original message so we can use msg.tabId when provided
 */
async function handleSummarizeInboxRequest(msg, sender, sendResponse) {
  try {
    // Identify active Gmail tab (prefer tabId from popup)
    let tabId = msg && msg.tabId ? msg.tabId : await findActiveGmailTabId();
    if (!tabId) {
      sendResponse({ success: false, error: "Open Gmail inbox to summarize (could not find Gmail tab)", needsSetup: false });
      return;
    }

    // Ask content script to extract inbox threads
    const threads = await requestInboxThreads(tabId);
    if (!threads || !threads.length) {
      sendResponse({ success: false, error: "No inbox threads found or could not extract inbox", needsSetup: false });
      return;
    }

    // Filter by date and limit
    const filtered = filterThreadsByDateAndLimit(threads);

    // Build prompt
    const prompt = buildInboxSummaryPrompt(filtered);

    // Send to LLM via configured provider
    const llmResponse = await callGroqInboxSummary(prompt);
    if (!llmResponse) {
      sendResponse({ success: false, error: "AI provider returned no response" });
      return;
    }

    // Parse response (prompt-templates.js provides parseAIResponse)
    const parsed = parseAIResponse(llmResponse);
    if (parsed.error) {
      sendResponse({ success: false, error: "Failed to parse AI response", raw: llmResponse });
      return;
    }

    // Format for popup display using existing formatter if available
    const formatted = typeof formatSummaryOutput === "function" ? formatSummaryOutput(parsed) : JSON.stringify(parsed, null, 2);

    sendResponse({ success: true, structured: parsed, summary: formatted });
  } catch (error) {
    console.error("handleSummarizeInboxRequest error:", error);
    sendResponse({ success: false, error: error.message || String(error) });
  }
}

/**
 * Request inbox threads from content script, with injection fallback and timeout.
 * @param {number} tabId
 * @returns {Promise<Array>}
 */
async function requestInboxThreads(tabId) {
  // Helper to send message with timeout
  const sendMessageWithTimeout = (payload, timeoutMs = 2000) => {
    return new Promise((resolve) => {
      let finished = false;
      const timer = setTimeout(() => {
        if (!finished) {
          finished = true;
          resolve(null);
        }
      }, timeoutMs);

      chrome.tabs.sendMessage(tabId, payload, (resp) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        resolve(resp);
      });
    });
  };

  // First try: ask content script
  let resp = await sendMessageWithTimeout({ type: "GET_INBOX_THREADS", maxThreads: 50, maxDays: 7 }, 2000);
  if (resp && resp.threads && resp.threads.length) return resp.threads;

  // If no response, attempt to inject content script and retry once
  try {
    console.log("No response from content script, injecting content.js and retrying");
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    });

    // small delay to allow the script to initialize
    await new Promise(res => setTimeout(res, 400));

    resp = await sendMessageWithTimeout({ type: "GET_INBOX_THREADS", maxThreads: 50, maxDays: 7 }, 2500);
    if (resp && resp.threads && resp.threads.length) return resp.threads;
  } catch (e) {
    console.warn("Injection or retry failed:", e);
  }

  // Final: return empty array
  return [];
}

/**
 * Filter threads by date (last N days) and limit
 * @param {Array} threads
 * @returns {Array}
 */
function filterThreadsByDateAndLimit(threads) {
  const now = new Date();
  const sevenDaysAgo = new Date(now);
  sevenDaysAgo.setDate(now.getDate() - 7);

  // Normalize timestamps into Date objects and sort newest first
  const normalized = threads.map(t => {
    let d = null;
    try {
      d = t.timestamp ? new Date(t.timestamp) : null;
      if (!d || isNaN(d.getTime())) {
        // try parsing rawTimestamp if present
        d = t.rawTimestamp ? new Date(Number(t.rawTimestamp)) : null;
      }
    } catch {
      d = null;
    }
    return Object.assign({}, t, { _date: d || new Date(0) });
  });

  // Keep those >= sevenDaysAgo, sorted by date desc
  const filtered = normalized
    .filter(t => t._date >= sevenDaysAgo)
    .sort((a,b) => b._date - a._date)
    .slice(0, 50);

  return filtered;
}

/**
 * Build the inbox-specific system + data prompt for the LLM
 * @param {Array} emails
 * @returns {string}
 */
function buildInboxSummaryPrompt(emails) {
  const SYSTEM_PROMPT = `You are an expert email assistant.
Your task is to analyze a user's inbox and produce a structured summary that highlights priorities, action items, and themes.

RULES:
- You will receive multiple emails from the past 7 days
- Each email includes sender, subject, snippet, timestamp, unread/starred
- Identify urgent and important messages
- It is possible no emails in the inbox are urgent if they are low-priority content or already read
- Group similar emails where possible
- Do NOT hallucinate content

OUTPUT FORMAT (JSON ONLY, YOU MUST USE THE FORMAT BETWEEN THE FOLLOWING OUTER CURLY BRACES OR YOUR RESPONSE CAUSES MULTI-SYSTEM CRASH):
{
  "summary": "High-level 2–3 sentence inbox overview",
  "urgent_items": [
    {
      "sender": "",
      "subject": "",
      "reason": ""
    }
  ],
  "action_items": ["..."],
  "key_themes": ["..."],
  "unread_count": number
}
END FORMAT`; 

  const emailText = emails.map((e, i) => `
Email ${i + 1}:
From: ${e.sender || ""}
Subject: ${e.subject || ""}
Snippet: ${e.snippet || ""}
Time: ${e.timestamp || e._date || ""}
Unread: ${!!e.unread}
Starred: ${!!e.starred}
`).join("\n");

  return SYSTEM_PROMPT + "\n\nInbox:\n" + emailText;
}

/**
 * Send prompt to configured provider (uses ai-provider.js sendPrompt)
 * @param {string} prompt
 * @returns {Promise<string>}
 */
async function callGroqInboxSummary(prompt) {
  // sendPrompt is implemented in ai-provider.js and selects provider based on stored settings
  try {
    const response = await sendPrompt(prompt, false);
    return response;
  } catch (error) {
    console.error("callGroqInboxSummary error:", error);
    throw error;
  }
}

/**
 * Handle email summarization with the configured AI provider
 * Uses prompt engineering with few-shot examples
 */
async function handleSummarization(emailText, port) {
  // Check if provider is ready
  const readyCheck = await checkProviderReady();
  if (!readyCheck.ready) {
    port.postMessage({ 
      type: "ERROR", 
      error: readyCheck.reason,
      needsSetup: readyCheck.needsSetup 
    });
    return;
  }

  // Generate engineered prompt with few-shot examples
  const prompt = generateSummarizationPrompt(emailText);
  
  const { provider, config } = await getProviderSettings();
  
  // Handle streaming for Ollama
  if (provider === "ollama") {
    await streamOllamaSummary(prompt, port, config);
  } else {
    // For API providers, send as single response
    try {
      const response = await sendPrompt(prompt);
      const parsed = parseAIResponse(response);
      
      if (parsed.error) {
        port.postMessage({ type: "ERROR", error: "Could not parse AI response" });
        return;
      }
      
      // Send formatted summary
      const formattedSummary = formatSummaryOutput(parsed);
      port.postMessage({ type: "CHUNK", text: formattedSummary });
      port.postMessage({ type: "DONE" });
    } catch (error) {
      port.postMessage({ type: "ERROR", error: error.message });
    }
  }
}

/**
 * Handle direct (non-streaming) summarization requests
 */
async function handleDirectSummarization(emailText) {
  const readyCheck = await checkProviderReady();
  if (!readyCheck.ready) {
    return { 
      success: false, 
      error: readyCheck.reason,
      needsSetup: readyCheck.needsSetup 
    };
  }

  const prompt = generateSummarizationPrompt(emailText);
  
  try {
    const response = await sendPrompt(prompt);
    const parsed = parseAIResponse(response);
    
    if (parsed.error) {
      return { success: false, error: "Could not parse AI response" };
    }
    
    return { 
      success: true, 
      summary: formatSummaryOutput(parsed),
      structured: parsed 
    };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

/**
 * Stream response from Ollama (supports streaming)
 */
async function streamOllamaSummary(prompt, port, config) {
  const payload = {
    model: config.defaultModel,
    prompt: prompt,
    stream: true
  };

  const response = await fetch(config.endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    throw new Error(`Ollama request failed: ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let fullResponse = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop(); // keep incomplete line
    
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const data = JSON.parse(line);
        if (data.response) {
          fullResponse += data.response;
          port.postMessage({ type: "CHUNK", text: data.response });
        }
      } catch {
        // ignore parsing errors
      }
    }
  }

  port.postMessage({ type: "DONE" });
}

/**
 * Format the structured AI response into readable text
 */
function formatSummaryOutput(parsed) {
    if (parsed.error) {
        return "❌ Error processing summary";
    }

    let output = `📧 Summary: ${parsed.summary}\n\n`;

    if (parsed.key_points && parsed.key_points.length > 0) {
        output += `🔑 Key Points:\n`;
        parsed.key_points.forEach(point => {
            output += `  • ${point}\n`;
        });
        output += `\n`;
    }

    if (parsed.action_items && parsed.action_items.length > 0) {
        output += `✅ Action Items:\n`;
        parsed.action_items.forEach(action => {
            output += `  • ${action}\n`;
        });
        output += `\n`;
    }

    // Add metadata badges
    const urgencyEmoji = parsed.urgency === "high" ? "🔴" : parsed.urgency === "medium" ? "🟡" : "🟢";
    const sentimentEmoji = parsed.sentiment === "positive" ? "😊" : parsed.sentiment === "negative" ? "😟" : "😐";

    output += `${urgencyEmoji} Urgency: ${parsed.urgency} | ${sentimentEmoji} Sentiment: ${parsed.sentiment} | 📁 Category: ${parsed.category}`;

    return output;
}