document.addEventListener("DOMContentLoaded", async () => {
    const messageBox = document.getElementById("message");
    const controls = document.getElementById("controls");
    const summarizeBtn = document.getElementById("summarizeBtn");
    const scanSpamBtn = document.getElementById("scanSpamBtn");
    const threatStatus = document.getElementById("threatStatus");

    // Helper to show message-only view
    function showOpenInboxMessage() {
        messageBox.innerHTML = "<p>❌ Open your inbox to see more.</p>";
        messageBox.classList.remove("hidden");
        controls.classList.add("hidden");
    }

    // get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) {
        showOpenInboxMessage();
        return;
    }

    // Try first: send a message to the page content script (fast if content script exists)
    let pageContext = null;
    try {
        const resp = await chrome.tabs.sendMessage(tab.id, { type: "GET_GMAIL_CONTEXT" });
        if (resp && resp.context) {
            pageContext = resp;
        }
    } catch (err) {
        // message failed — content script may not be ready or not injected — we'll fallback to executeScript
        console.warn("sendMessage failed; will try executeScript fallback.", err);
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
                        const nav = document.querySelector('[role="navigation"]') || document.querySelector('div[aria-label="Main menu"]');
                        if (nav) {
                            const navText = nav.innerText || "";
                            if (/inbox/i.test(navText)) {
                                const listArea = document.querySelector('div[role="main"]') || document.querySelector('div[role="list"]') || document.querySelector('.aeF');
                                if (listArea && listArea.innerText.trim().length > 0) {
                                    const openedMessage = document.querySelector('div[role="main"] [data-message-id], div[role="main"] .ii .a3s, div[role="main"] .adn');
                                    if (openedMessage) {
                                        return { context: "email", reason: "opened-message-detected" };
                                    }
                                    return { context: "inbox", reason: "inbox-list-detected" };
                                }
                            }
                        }
                        const hash = location.hash || location.pathname || "";
                        if (/#inbox\b|\/#inbox/i.test(hash)) {
                            return { context: "inbox", reason: "url-hint" };
                        }
                        if (/#(thread|message|inbox)\/\d+/.test(hash) || /#inbox\/\w+/.test(hash)) {
                            return { context: "email", reason: "url-message-id" };
                        }
                    } catch (e) {
                        return { context: "none", reason: "error", error: String(e) };
                    }
                    return { context: "inbox", reason: "fallback" };
                }
            });

            // executeScript returns an array of result objects (one per frame)
            if (results && results[0] && results[0].result) pageContext = results[0].result;
        } catch (err) {
            console.error("executeScript failed:", err);
        }
    }

    // No Gmail context found
    if (!pageContext || pageContext.context === "none") {
        showOpenInboxMessage();
        return;
    }

    // Otherwise show controls and adapt labels
    messageBox.classList.add("hidden");
    controls.classList.remove("hidden");

    // Label adapt
    summarizeBtn.textContent = pageContext.context === "email" ? "Summarize Email" : "Summarize Inbox";

    // Start an automatic "threat scan" simulation with placeholder logic
    threatStatus.className = "status neutral";
    threatStatus.innerHTML = "<p>Scanning...</p>";

    setTimeout(async () => {
        // Ask content script for link scan if available; else simulate
        let scanResp = null;
        try {
            scanResp = await chrome.tabs.sendMessage(tab.id, { type: "SCAN_LINKS" }, { timeout: 2000 }).catch(() => null);
        } catch (e) {
            scanResp = null;
        }

        if (scanResp && scanResp.result) {
            const { level, detail } = scanResp.result;
            threatStatus.className = `status ${level}`;
            threatStatus.innerHTML = `<p>${detail}</p>`;
        } else {
            threatStatus.className = "status neutral";
            threatStatus.innerHTML = "<p>Unable to scan links. Please reload the page or check your connection.</p>";
        }
    }, 750);

    // Summarize button handler (stub)
    summarizeBtn.addEventListener("click", async () => {
        summarizeBtn.disabled = true;
        summarizeBtn.textContent = (pageContext.context === "email" ? "Summarizing Email..." : "Summarizing Inbox...");
        // stub delay
        setTimeout(() => {
            summarizeBtn.disabled = false;
            summarizeBtn.textContent = pageContext.context === "email" ? "Summarize Email" : "Summarize Inbox";
            // In future: sendMessage to content script to extract text and run LLM
            alert("Summary (stub): This is a placeholder summary.");
        }, 1200);
    });

    // Scan for Spam handler - request content script to find unsubscribe link
    scanSpamBtn.addEventListener("click", async () => {
        scanSpamBtn.disabled = true;
        scanSpamBtn.textContent = "Scanning...";
        try {
            const resp = await chrome.tabs.sendMessage(tab.id, { type: "SCAN_SPAM" }, { timeout: 3000 }).catch(() => null);
            if (resp && resp.unsubscribeLink) {
                scanSpamBtn.textContent = "Unsubscribe here!";
                // copy link to clipboard
                try {
                    await navigator.clipboard.writeText(resp.unsubscribeLink);
                } catch (e) {
                    console.warn("Clipboard write failed:", e);
                }
                // Optionally open the link or send response back
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
});

async function getActiveTab() {
    let [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return tab;
}

// Update popup UI based on Gmail context
async function updateUI() {
    const tab = await getActiveTab();
    const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
            const url = window.location.href;
            if (!url.includes("mail.google.com")) return "notGmail";
            if (url.includes("#inbox")) return "inbox";
            if (url.includes("#inbox/") || url.includes("#sent/")) return "email";
            return "otherGmail";
        }
    });

    const contextLabel = document.getElementById("contextLabel");
    const summarizeBtn = document.getElementById("summarizeBtn");

    switch (result) {
        case "inbox":
            contextLabel.textContent = "📥 Gmail Inbox Detected";
            summarizeBtn.textContent = "Summarize Inbox";
            break;
        case "email":
            contextLabel.textContent = "📧 Individual Email Detected";
            summarizeBtn.textContent = "Summarize This Email";
            break;
        case "notGmail":
            contextLabel.textContent = "❌ Not a Gmail Page";
            summarizeBtn.disabled = true;
            break;
        default:
            contextLabel.textContent = "⚙️ Gmail (Other Section)";
    }
}

// Stub: summarization click
document.getElementById("summarizeBtn").addEventListener("click", async () => {
    const tab = await getActiveTab();
    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => alert("Summarization placeholder: to be implemented")
    });
});

// Spam / unsubscribe scan
document.getElementById("spamBtn").addEventListener("click", async () => {
    const tab = await getActiveTab();
    chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
            const links = [...document.querySelectorAll("a[href]")];
            const unsubLinks = links.filter(a =>
                /unsubscribe|optout|preferences/i.test(a.href)
            );
            if (unsubLinks.length) {
                alert(`Found ${unsubLinks.length} unsubscribe link(s):\n\n` +
                    unsubLinks.map(a => a.href).join("\n"));
                unsubLinks[0].click(); // example: open first unsubscribe link
            } else {
                alert("No unsubscribe links found in this email.");
            }
        }
    });
});

// Phishing scan
document.getElementById("phishBtn").addEventListener("click", async () => {
    const tab = await getActiveTab();
    const [{ result }] = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
            const links = [...document.querySelectorAll("a[href]")];
            let suspicious = 0;
            let total = 0;
            const suspiciousDomains = [/login|verify|secure/i, /\.ru$|\.cn$|\.tk$/i];
            for (const a of links) {
                total++;
                const text = (a.innerText || "").trim();
                const href = a.href;
                if (!href) continue;
                if (text && !href.includes(text) && text.length > 4) suspicious++;
                if (suspiciousDomains.some(r => r.test(href))) suspicious++;
            }
            const score = total ? suspicious / total : 0;
            return score;
        }
    });

    const indicator = document.getElementById("threatIndicator");
    if (result < 0.2) {
        indicator.textContent = "Low Threat";
        indicator.className = "status green";
    } else if (result < 0.5) {
        indicator.textContent = "Moderate Threat";
        indicator.className = "status yellow";
    } else {
        indicator.textContent = "High Threat!";
        indicator.className = "status red";
    }
});

updateUI();
