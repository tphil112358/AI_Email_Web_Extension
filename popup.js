document.addEventListener("DOMContentLoaded", async () => {
    const messageBox = document.getElementById("message");
    const controls = document.getElementById("controls");
    const summarizeBtn = document.getElementById("summarizeBtn");
    const scanSpamBtn = document.getElementById("scanSpamBtn");
    const threatStatus = document.getElementById("threatStatus");
    const securityWindow = document.getElementById("security-window");
    const securityBody = document.getElementById("security-body");
    const summaryOutputEl = document.getElementById("summary-output");

    // Keep page context available for branching between email vs inbox summarization
    let pageContext = null;

    // Helper: send message to tab with an explicit JS timeout (do NOT pass a { timeout } options object to chrome.tabs.sendMessage)
    // This helper is defined before any sendMessage usage so it always exists.
    async function sendMessageToTab(tabId, message, timeoutMs = 2000) {
      return new Promise((resolve, reject) => {
        let finished = false;
        const timer = setTimeout(() => {
          if (finished) return;
          finished = true;
          resolve(null); // timeout -> treat as no response
        }, timeoutMs);

        try {
          chrome.tabs.sendMessage(tabId, message, (resp) => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            // If chrome.runtime.lastError is set, treat it as no response
            if (chrome.runtime && chrome.runtime.lastError) {
              resolve(null);
            } else {
              resolve(resp);
            }
          });
        } catch (err) {
          if (!finished) {
            finished = true;
            clearTimeout(timer);
          }
          reject(err);
        }
      });
    }

    // Helper to show message-only view
    function showOpenInboxMessage() {
        if (messageBox) {
            messageBox.innerHTML = "<p>❌ Open your inbox to see more.</p>";
            messageBox.classList.remove("hidden");
        }
        if (controls) {
            controls.classList.add("hidden");
        }
    }

    // Summary visibility helpers: start hidden, only show when actual summary content exists
    function hideSummary() {
        if (!summaryOutputEl) return;
        summaryOutputEl.textContent = "";
        summaryOutputEl.classList.add("hidden");
    }
    function showSummary(text) {
        if (!summaryOutputEl) return;
        // Hide any top-level message so summary can be primary focus
        if (messageBox) messageBox.classList.add("hidden");
        summaryOutputEl.textContent = text;
        summaryOutputEl.classList.remove("hidden");
    }

    // Ensure summary area is hidden until a summary is produced
    hideSummary();

    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
        showOpenInboxMessage();
        return;
    }
    
    // Check if we're on a Chrome URL (can't inject scripts here)
    if (tab.url && (tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://") || tab.url.startsWith("about:"))) {
        showOpenInboxMessage();
        if (messageBox) {
            messageBox.innerHTML = "<p>❌ Extension cannot run on Chrome system pages.<br><br>Please open Gmail to use Aegis One.</p>";
        }
        return;
    }

    // Try first: send a message to the page content script (fast if content script exists)
    try {
        // Use helper to avoid passing unsupported options to chrome.tabs.sendMessage
        const resp = await sendMessageToTab(tab.id, { type: "GET_GMAIL_CONTEXT" }, 1200);
        if (resp && resp.context) {
            pageContext = resp;
        }
    } catch (err) {
        // Message failed — content script may not be ready or not injected
        // This is expected on first load or non-Gmail pages - will use fallback
        console.log("Content script not responding, using fallback detection");
    }

    // Fallback: run detection directly in page using scripting.executeScript
    if (!pageContext) {
        try {
            const results = await chrome.scripting.executeScript({
                target: { tabId: tab.id },
                func: () => {
                    // This runs in the page; replicate the robust detection function inline
                    if (!location.hostname.includes("mail.google.com")) {
                        return { context: "none", reason: "not-gmail-host" };
                    }
                    
                    try {
                        const hash = location.hash || "";
                        
                        // Check URL hash first - most reliable indicator
                        // Individual email patterns: #inbox/messageId, #sent/messageId, etc.
                        if (/#(inbox|sent|drafts|spam|trash|label\/[^/]+)\/[A-Za-z0-9]+/.test(hash)) {
                            return { context: "email", reason: "url-message-id" };
                        }
                        
                        // Inbox list patterns
                        if (/^#(inbox|sent|drafts|spam|trash|starred|important|snoozed|label\/[^/]+)$/.test(hash)) {
                            return { context: "inbox", reason: "url-list-view" };
                        }
                        
                        // Check for opened email in DOM
                        const messageBody = document.querySelector('div[role="main"] .ii.gt, div[role="main"] .a3s.aiL, div[role="main"] [data-message-id]');
                        if (messageBody && messageBody.offsetHeight > 100) {
                            return { context: "email", reason: "message-body-detected" };
                        }
                        
                        // Check for email list view
                        const emailRows = document.querySelectorAll('table[role="grid"] tr.zA, div[role="main"] table tr[role="row"]');
                        if (emailRows.length > 3) {
                            return { context: "inbox", reason: "email-list-detected" };
                        }
                        
                        // Default to none if we can't confidently determine context
                        return { context: "none", reason: "unable-to-detect" };
                    } catch (e) {
                        return { context: "none", reason: "error", error: String(e) };
                    }
                }
            });

            // executeScript returns an array of result objects (one per frame)
            if (results && results[0] && results[0].result) pageContext = results[0].result;
        } catch (err) {
            console.error("executeScript failed:", err);
            // If script execution fails, we're probably not on Gmail
            showOpenInboxMessage();
            return;
        }
    }

    // No Gmail context found
    if (!pageContext || pageContext.context === "none") {
        showOpenInboxMessage();
        return;
    }

    // Otherwise show controls and adapt labels
    if (messageBox) messageBox.classList.add("hidden");
    if (controls) controls.classList.remove("hidden");

    // Label adapt
    if (summarizeBtn && pageContext) {
        summarizeBtn.textContent = pageContext.context === "email" ? "Summarize Email" : "Summarize Inbox";
    }

    // Initialize security window
    function setSecurityState(level, text) {
        if (!securityWindow || !securityBody) return;
        securityWindow.classList.remove("neutral", "warning", "alert", "danger", "safe");
        if (level === "safe" || level === "green" || level === "neutral") {
            securityWindow.classList.add("neutral");
            securityBody.textContent = text || "Checks out! ✅";
        } else if (level === "warning" || level === "yellow") {
            securityWindow.classList.add("warning");
            securityBody.textContent = text || "Potential issues detected.";
        } else {
            securityWindow.classList.add("alert");
            securityBody.textContent = text || "Potentially malicious activity detected.";
        }
    }

    setSecurityState("neutral", "Checking...");

    setTimeout(async () => {
        if (!securityBody) return;
        
        // If inbox view use the background AI-powered inbox threat scan
        if (pageContext.context === "inbox") {
            try {
                const response = await chrome.runtime.sendMessage({ type: "SCAN_INBOX_THREATS", tabId: tab.id });
                if (response && response.result) {
                    const { level, detail, findings } = response.result;
                    const summaryText = detail || (findings && findings.length ? `Found ${findings.length} suspicious items` : "Checks out! ✅");
                    setSecurityState(level, summaryText);
                } else {
                    setSecurityState("neutral", "Unable to scan inbox. Please reload the page or check your connection.");
                }
            } catch (err) {
                console.warn("Inbox threat scan failed:", err);
                setSecurityState("neutral", "Unable to scan inbox. Please reload the page or check your connection.");
            }
            return;
        }

        // Otherwise single-email view — ask content script to quick-scan links
        try {
            // Use helper (avoids unsupported options object)
            const scanResp = await sendMessageToTab(tab.id, { type: "SCAN_LINKS" }, 1200);
            if (scanResp && scanResp.result) {
                const { level, detail, links } = scanResp.result;
                if (level === "safe") {
                    setSecurityState("safe", "Checks out! ✅");
                } else if (level === "warning") {
                    const reason = detail || (links && links[0] && links[0].reason) || "Suspicious links detected";
                    setSecurityState("warning", reason);
                } else {
                    const reason = detail || (links && links[0] && links[0].reason) || "Potentially malicious links detected";
                    setSecurityState("alert", reason);
                }
            } else {
                setSecurityState("neutral", "Unable to scan links. Please reload the page or check your connection.");
            }
        } catch (err) {
            console.warn("Link scan failed:", err);
            setSecurityState("neutral", "Unable to scan links. Please reload the page or check your connection.");
        }
    }, 750);

    // Inbox summarization handler (called when summarize button is clicked and context is inbox)
    async function onSummarizeInboxClicked() {
        summarizeBtn.disabled = true;
        const originalText = summarizeBtn.textContent;
        summarizeBtn.textContent = "Summarizing inbox...";

        // Keep the summary output hidden until we actually have a summary to display
        hideSummary();

        try {
            // Pass the active tab id to the background so it targets the right Gmail tab/frame
            if (!tab || !tab.id) {
                if (messageBox) {
                    messageBox.textContent = "❌ Unable to determine current tab. Make sure Gmail is open and active.";
                    messageBox.classList.remove("hidden");
                }
                return;
            }

            const response = await chrome.runtime.sendMessage({ type: "SUMMARIZE_INBOX_REQUEST", tabId: tab.id });
            if (!response) {
                if (messageBox) {
                    messageBox.textContent = "❌ No response from background.";
                    messageBox.classList.remove("hidden");
                }
                return;
            }

            if (response.success) {
                renderInboxSummary(response.structured || response.parsed || response.summary || response);
            } else {
                const err = response.error || response.reason || "Unknown error";
                if (messageBox) {
                    messageBox.textContent = `❌ ${err}`;
                    messageBox.classList.remove("hidden");
                }
            }
        } catch (err) {
            if (messageBox) {
                messageBox.textContent = `❌ ${err.message || String(err)}`;
                messageBox.classList.remove("hidden");
            }
        } finally {
            summarizeBtn.disabled = false;
            summarizeBtn.textContent = originalText;
        }
    }

    // Render structured inbox summary JSON into the popup UI
    function renderInboxSummary(parsed) {
        try {
            // Build text
            const summary = parsed.summary || parsed.overview || "Inbox summary unavailable";
            const urgent = parsed.urgent_items || parsed.urgent || [];
            const actions = parsed.action_items || parsed.action_items || parsed.actions || [];
            const themes = parsed.key_themes || parsed.themes || [];
            const unread = typeof parsed.unread_count === "number" ? parsed.unread_count : (parsed.unread || 0);

            let text = `📧 ${summary}\n\n`;
            if (urgent && urgent.length) {
                text += `🚨 Urgent Items:\n`;
                urgent.slice(0,5).forEach(item => {
                    const sender = item.sender || item.from || "";
                    const subject = item.subject || "";
                    const reason = item.reason || "";
                    text += ` • ${subject} — ${sender}${reason ? " (" + reason + ")" : ""}\n`;
                });
                text += `\n`;
            }

            if (actions && actions.length) {
                text += `✅ Action Items:\n`;
                actions.forEach(a => text += ` • ${a}\n`);
                text += `\n`;
            }

            if (themes && themes.length) {
                text += `🔎 Key Themes:\n`;
                themes.forEach(t => text += ` • ${t}\n`);
                text += `\n`;
            }

            text += `✉️ Unread: ${unread}`;

            showSummary(text);
        } catch (e) {
            if (messageBox) {
                messageBox.textContent = "❌ Failed to render summary";
                messageBox.classList.remove("hidden");
            }
            console.error("renderInboxSummary error:", e);
        }
    }

    // Existing summarize button handler - branch by context (email vs inbox)
    document.getElementById("summarizeBtn")?.addEventListener("click", async () => {
      // If we determined earlier that context is inbox, use the inbox summarizer
      if (pageContext && pageContext.context === "inbox") {
          await onSummarizeInboxClicked();
          return;
      }

      // Otherwise fall back to existing per-email summarization flow (unchanged behavior,
      // but summary area remains hidden until actual summary chunks arrive)
      if (messageBox) {
          messageBox.textContent = "⏳ Checking AI provider...";
          messageBox.classList.remove("hidden");
      }
    
      // Check if AI provider is configured and ready
      try {
        const response = await chrome.runtime.sendMessage({ type: "CHECK_PROVIDER" });
        
        if (response && response.needsSetup) {
          if (messageBox) {
            messageBox.innerHTML = `⚠️ ${response.reason}<br><br><button id="openSettingsBtn" style="padding: 8px 16px; background: #58a6ff; border: none; border-radius: 6px; color: #0d1117; cursor: pointer; font-weight: 600;">Open Settings</button>`;
            messageBox.classList.remove("hidden");
            if (document.getElementById("openSettingsBtn")) {
              document.getElementById("openSettingsBtn").addEventListener("click", () => {
                chrome.tabs.create({ url: chrome.runtime.getURL("settings.html") });
              });
            }
          }
          return;
        }
      } catch (error) {
        // Continue if check fails - will try to use default provider
        console.warn("Provider check failed:", error);
      }
      
      if (messageBox) {
        messageBox.textContent = "⏳ Extracting email...";
        messageBox.classList.remove("hidden");
      }
    
      // Ask content script to extract the email text
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      
      try {
        let response;
        
        // Try to send message to content script
        try {
          response = await sendMessageToTab(tab.id, { type: "SUMMARIZE_EMAIL" }, 1500);
        } catch (connectionError) {
          // Content script not loaded - inject it manually
          console.log("Content script not loaded, injecting manually...");
          
          try {
            await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              files: ['content.js']
            });
            
            // Wait a moment for script to initialize
            await new Promise(resolve => setTimeout(resolve, 500));
            
            // Try sending message again
            response = await sendMessageToTab(tab.id, { type: "SUMMARIZE_EMAIL" }, 1500);
          } catch (injectError) {
            if (messageBox) {
              messageBox.textContent = "⚠️ Failed to load email scanner. Please reload Gmail and try again.";
              messageBox.classList.remove("hidden");
            }
            console.error("Script injection failed:", injectError);
            return;
          }
        }
        
        if (!response || !response.success) {
          const errorMsg = response?.error || "Could not extract email text.";
          if (messageBox) {
            messageBox.textContent = `⚠️ ${errorMsg}`;
            messageBox.classList.remove("hidden");
          }
          console.error("Email extraction failed:", response);
          return;
        }
        
        if (messageBox) {
          messageBox.textContent = "⏳ Summarizing with AI...";
          messageBox.classList.remove("hidden");
        }
    
        // Open a port for streaming
        const port = chrome.runtime.connect({ name: "ollamaStream" });
        port.postMessage({ type: "SUMMARIZE_TEXT", text: response.text });
    
        let fullSummary = "";
        let seenFirstChunk = false;
    
        port.onMessage.addListener((msg) => {
          if (msg.type === "CHUNK") {
            fullSummary += msg.text;
            if (!seenFirstChunk) {
              // Only unhide summary area once we actually have content
              showSummary(fullSummary);
              seenFirstChunk = true;
            } else if (summaryOutputEl) {
              summaryOutputEl.textContent = fullSummary;
            }
          } else if (msg.type === "DONE") {
            // Finalize and show trimmed content
            showSummary(fullSummary.trim() || "No summary received.");
          } else if (msg.type === "ERROR") {
            // Errors do not cause the summary panel to be shown per new UX requirement
            if (msg.needsSetup) {
              if (messageBox) {
                messageBox.innerHTML = `❌ ${msg.error}<br><br><button id="openSettingsBtn" style="padding: 8px 16px; background: #58a6ff; border: none; border-radius: 6px; color: #0d1117; cursor: pointer; font-weight: 600;">Configure AI Provider</button>`;
                messageBox.classList.remove("hidden");
                document.getElementById("openSettingsBtn")?.addEventListener("click", () => {
                  chrome.tabs.create({ url: chrome.runtime.getURL("settings.html") });
                });
              }
            } else {
              if (messageBox) {
                messageBox.textContent = "❌ " + msg.error;
                messageBox.classList.remove("hidden");
              }
            }
          }
        });
      } catch (error) {
        if (messageBox) {
          messageBox.textContent = `⚠️ Error: ${error.message || String(error)}`;
          messageBox.classList.remove("hidden");
        }
        console.error("Summarization error:", error);
      }
    });

    // Scan for Spam handler - request content script to find unsubscribe link
    function formatLinkForDisplay(url, maxLength = 40) {
    try {
        const { hostname, pathname } = new URL(url);
        const display = `${hostname}${pathname}`;
        return display.length > maxLength
            ? display.slice(0, maxLength) + "…"
            : display;
    } catch {
        return "Open unsubscribe link";
    }
    }
    
    let pendingUnsubscribeLink = null;
    
    if (scanSpamBtn) {
        scanSpamBtn.addEventListener("click", async () => {
        
            // SECOND CLICK: open the link
            if (pendingUnsubscribeLink) {
                chrome.tabs.create({
                    url: pendingUnsubscribeLink,
                    active: true
                });
            
                // Reset button state after navigation
                pendingUnsubscribeLink = null;
                scanSpamBtn.textContent = "Scan for spam";
                scanSpamBtn.disabled = false;
                return;
            }
        
            // FIRST CLICK: scan inbox
            scanSpamBtn.disabled = true;
            scanSpamBtn.textContent = "Scanning...";
        
            try {
                const resp = await sendMessageToTab(
                    tab.id,
                    { type: "SCAN_SPAM" },
                    1500
                );
            
                if (resp && resp.unsubscribeLink) {
                    pendingUnsubscribeLink = resp.unsubscribeLink;
                
                    scanSpamBtn.textContent =
                        formatLinkForDisplay(resp.unsubscribeLink);
                    scanSpamBtn.disabled = false;
                
                } else {
                    scanSpamBtn.textContent = "No unsubscribe link found";
                    scanSpamBtn.disabled = true;
                }
            } catch (err) {
                console.warn("SCAN_SPAM failed:", err);
                scanSpamBtn.textContent = "No unsubscribe link found";
                scanSpamBtn.disabled = true;
            }
        });
    }


    
    // Phishing scan handler
    document.getElementById("phishBtn")?.addEventListener("click", async () => {
        const indicator = document.getElementById("threatIndicator");
        if (!indicator) return;
        
        indicator.textContent = "Scanning for threats...";
        indicator.className = "status neutral";
        
        try {
            if (pageContext && pageContext.context === "inbox") {
                const resp = await chrome.runtime.sendMessage({ type: "SCAN_INBOX_THREATS", tabId: tab.id });
                if (resp && resp.result) {
                    const { level, detail } = resp.result;
                    indicator.className = `status ${level === "safe" ? "safe" : level === "warning" ? "warning" : "danger"}`;
                    indicator.textContent = detail;
                } else {
                    indicator.className = "status neutral";
                    indicator.textContent = "Unable to scan. Please reload the page.";
                }
            } else {
                const resp = await sendMessageToTab(tab.id, { type: "SCAN_LINKS" }, 1500);
                
                if (resp && resp.result) {
                    const { level, detail } = resp.result;
                    indicator.className = `status ${level === "safe" ? "safe" : level === "warning" ? "warning" : "danger"}`;
                    indicator.textContent = detail;
                } else {
                    indicator.className = "status neutral";
                    indicator.textContent = "Unable to scan. Please reload the page.";
                }
            }
        } catch (err) {
            console.warn("Threat scan failed:", err);
            indicator.className = "status neutral";
            indicator.textContent = "Scan failed. Please reload the page.";
        }
    });
});

// Settings button handler
document.getElementById("settingsBtn")?.addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("settings.html") });
});
