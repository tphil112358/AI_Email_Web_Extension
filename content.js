// content.js

// Robust Gmail context detection
function detectGmailContextContent() {
    if (!location.hostname.includes("mail.google.com")) {
        return { context: "none", reason: "not-gmail-host" };
    }
    
    try {
        const hash = location.hash || "";
        
        // Check URL hash first - most reliable indicator
        // Individual email patterns: #inbox/messageId, #sent/messageId, #label/xyz/messageId
        if (/#(inbox|sent|drafts|spam|trash|label\/[^/]+)\/[A-Za-z0-9]+/.test(hash)) {
            return { context: "email", reason: "url-message-id" };
        }
        
        // Inbox list patterns: #inbox (without trailing slash/ID), #search, #label
        if (/^#(inbox|sent|drafts|spam|trash|starred|important|snoozed|label\/[^/]+)$/.test(hash)) {
            return { context: "inbox", reason: "url-list-view" };
        }
        
        // Check for opened email in DOM - Gmail shows full message body
        const messageBody = document.querySelector('div[role="main"] .ii.gt, div[role="main"] .a3s.aiL, div[role="main"] [data-message-id]');
        if (messageBody && messageBody.offsetHeight > 100) {
            // Verify it's actually visible and has substantial content
            return { context: "email", reason: "message-body-detected" };
        }
        
        // Check for email list view - multiple email rows
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

// --- SPAM MODULE: unsubscribe link detection ---
function findUnsubscribeLink() {
    const relUnsub = Array.from(document.querySelectorAll('a[rel~="unsubscribe"]')).map(a => a.href).filter(Boolean);
    if (relUnsub.length) return relUnsub[0];

    const anchors = Array.from(document.querySelectorAll('a[href]'));
    for (const a of anchors) {
        const text = (a.textContent || "").trim().toLowerCase();
        if (/unsubscribe/i.test(text)) return a.href;
    }

    for (const a of anchors) {
        if (/\/unsubscribe|unsubscribe=true|list-unsubscribe/i.test(a.href)) return a.href;
    }

    return null;
}

// --- PHISHING MODULE: URL deception analysis ---
/**
 * Analyzes links for deceptive practices by comparing visible text with actual URLs.
 * Performs basic logical checks (no AI).
 *
 * @param {Array} links - Array of objects with { href: string, text: string }
 * @returns {Object} - { suspiciousLinks: [...], threatLevel: "safe"|"warning"|"danger", analyzed }
 */
function analyzeUrlDeception(links) {
    const shorteners = [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "short.url", "is.gd", "buff.ly", "tiny.one"
    ];
    const knownBad = [
        "malware.example", "badware.test", "phishingsite.test" // small placeholder list — expand offline
    ];

    const urlLikeRegex = /\bhttps?:\/\/[^\s/$.?#].[^\s]*\b|(?:www\.)[^\s/$.?#].[^\s]*\b/gi;
    const suspiciousLinks = [];

    for (let i = 0; i < links.length; i++) {
        const { href = "", text = "" } = links[i];
        const indicators = [];
        let hrefHostname = "";
        try {
            hrefHostname = new URL(href).hostname.toLowerCase();
        } catch {
            // not a valid absolute URL; may be relative or javascript:
        }

        // If visible text looks like a URL (plaintext) and differs from actual href destination
        const textUrls = (text || "").match(urlLikeRegex) || [];
        if (textUrls.length > 0) {
            // compare first URL-like appearance to href
            try {
                const visible = textUrls[0];
                let visibleHost = "";
                try {
                    visibleHost = new URL(visible.startsWith("http") ? visible : "http://" + visible).hostname.toLowerCase();
                } catch { visibleHost = ""; }

                if (visibleHost && hrefHostname && visibleHost !== hrefHostname) {
                    indicators.push("text-URL mismatch (visible plaintext differs from href)");
                }
            } catch (e) {
                // ignore
            }
        }

        // Shortener detection
        if (hrefHostname && shorteners.some(s => hrefHostname.includes(s))) {
            indicators.push("URL shortener detected");
        }

        // Suspicious or known-bad domains
        if (hrefHostname && knownBad.some(b => hrefHostname.includes(b))) {
            indicators.push("known malicious domain");
        }

        // Subdomain tricks: many random strings or hyphen prefixes like login- or secure-
        if (/login-|secure-|verify-|account-|signin-/.test(hrefHostname)) {
            indicators.push("suspicious auth-related subdomain pattern");
        }

        // Non-HTTPS usage (not conclusively malicious but informative)
        if (href && href.startsWith("http://")) {
            indicators.push("uses http (not https)");
        }

        if (indicators.length) {
            suspiciousLinks.push({
                index: i,
                href,
                text,
                reason: indicators.join("; "),
                indicators
            });
        }
    }

    // Scoring heuristics
    let threatLevel = "safe";
    if (suspiciousLinks.length >= 2) threatLevel = "danger";
    else if (suspiciousLinks.length === 1) {
        // escalate to danger if contains known malicious or strong indicators
        const first = suspiciousLinks[0];
        if (first.indicators.includes("known malicious domain") || first.indicators.includes("URL shortener detected") || first.indicators.includes("text-URL mismatch (visible plaintext differs from href)")) {
            threatLevel = "danger";
        } else {
            threatLevel = "warning";
        }
    }

    return {
        suspiciousLinks,
        threatLevel,
        analyzed: links.length
    };
}

// --- PHISHING MODULE: simple heuristic link scan ---
function quickScanLinks() {
    const anchors = Array.from(document.querySelectorAll('a[href]')).slice(0, 200);
    
    // Prepare links for deception analysis
    const linksToAnalyze = anchors.map(a => ({
        href: a.href || "",
        text: (a.textContent || "").trim()
    }));
    
    // Use the deception analysis function
    const deception = analyzeUrlDeception(linksToAnalyze);
    
    const suspiciousLinks = deception.suspiciousLinks.map(s => ({
        href: s.href,
        reason: s.reason,
        indicators: s.indicators
    }));

    const level = deception.threatLevel === "danger" ? "danger" : deception.threatLevel === "warning" ? "warning" : "safe";
    const detail = level === "safe" ? "✅ No suspicious links detected." : (suspiciousLinks.length ? `${suspiciousLinks.length} suspicious link(s): ${suspiciousLinks.slice(0,3).map(s => s.reason).join(", ")}` : "Potentially suspicious links found.");

    return { level, detail, links: suspiciousLinks };
}

// --- SUMMARIZE MODULE: prototype ---
async function summarizeCurrentEmail() {
    const messageBody = document.querySelector('div[role="main"] .ii .a3s, div[role="main"] [data-message-id]');
    if (!messageBody) {
        return { success: false, summary: null, error: "No open email detected" };
    }

    // Extract visible text (strip inline reply junk)
    let text = messageBody.innerText.trim();
    if (!text || text.length < 50) {
        return { success: false, summary: null, error: "Email content too short or empty" };
    }

    // Stubbed Ollama call
    const fakeSummary = text.length > 300
        ? text.slice(0, 200) + "... [summary truncated for prototype]"
        : "This is a placeholder summary. The real version will summarize using Ollama.";

    // In the real version, we’ll do something like:
    // const response = await fetch('http://localhost:11434/api/generate', { method: 'POST', body: JSON.stringify({ prompt: `Summarize: ${text}` }) });
    // const result = await response.json();

    return { success: true, summary: fakeSummary };
}

// --- INBOX EXTRACTION ---
function extractInboxThreads(maxThreads = 50, maxDays = 7) {
    const rows = Array.from(document.querySelectorAll('tr.zA, table[role="grid"] tr.zA')).filter(Boolean);
    const results = [];
    const now = new Date();
    const sevenDaysAgo = new Date(now);
    sevenDaysAgo.setDate(now.getDate() - (maxDays || 7));

    for (const row of rows) {
        if (results.length >= maxThreads) break;

        // Sender
        const sender = row.querySelector('.yW span, .yX.xY span')?.innerText?.trim() || row.querySelector('.yP')?.innerText?.trim() || "";

        // Subject
        const subject = row.querySelector('.y6 span')?.innerText?.trim() || row.querySelector('.bog')?.innerText?.trim() || "";

        // Snippet
        const snippet = row.querySelector('.y2')?.innerText?.trim() || row.querySelector('.yW + .y2')?.innerText?.trim() || "";

        // Unread
        const unread = row.classList.contains('zE') || row.classList.contains('unread');

        // Starred
        const starred = !!row.querySelector('.T-KT, .asa');

        // Timestamp: Gmail often stores a title or aria-label on the time element
        let timestamp = null;
        const timeEl = row.querySelector('td.xW span, td.xW .xW span, .xW span');
        if (timeEl) {
            timestamp = timeEl.getAttribute('title') || timeEl.getAttribute('aria-label') || timeEl.innerText || null;
        }

        // Fallback to data-timestamp attribute if present
        const rawTimestamp = row.getAttribute('data-timestamp') || null;

        // Try to skip older than maxDays quickly if timestamp can be parsed
        let parsedDate = null;
        if (timestamp) {
            const d = new Date(timestamp);
            if (!isNaN(d.getTime())) parsedDate = d;
        } else if (rawTimestamp) {
            const n = Number(rawTimestamp);
            if (!isNaN(n)) parsedDate = new Date(n);
        }

        if (parsedDate && parsedDate < sevenDaysAgo) {
            // skip older thread
            continue;
        }

        results.push({
            sender,
            subject,
            snippet,
            timestamp,
            rawTimestamp,
            unread,
            starred
        });
    }

    return results;
}

// --- MESSAGE HANDLERS ---
console.log("Aegis One content script loaded and ready");

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    console.log("Content script received message:", msg.type);
    
    if (msg.type === "GET_GMAIL_CONTEXT") {
        const result = detectGmailContextContent();
        console.log("Gmail context detection result:", result);
        sendResponse(result);
        return true;
    }

    if (msg.type === "SCAN_SPAM") {
        const link = findUnsubscribeLink();
        console.log("Unsubscribe link found:", link);
        sendResponse({ unsubscribeLink: link });
        return true;
    }

    if (msg.type === "SCAN_LINKS") {
        const result = quickScanLinks();
        console.log("Link scan result:", result);
        sendResponse({ result });
        return true;
    }

    if (msg.type === "GET_INBOX_THREADS") {
        const threads = extractInboxThreads(msg.maxThreads || 50, msg.maxDays || 7);
        console.log("Extracted inbox threads:", threads.length);
        sendResponse({ threads });
        return true;
    }

    if (msg.type === "SUMMARIZE_EMAIL") {
        const ctx = detectGmailContextContent();
        if (ctx.context !== "email") {
            console.log("Not on email view, context:", ctx);
            sendResponse({ success: false, reason: "not-on-email", error: "Not viewing an individual email" });
            return true;
        }

        // Try multiple selectors for Gmail email body (Gmail's DOM varies)
        const selectors = [
            'div[role="main"] div.a3s.aiL',           // Primary message body
            'div[role="main"] div.ii.gt',              // Full message container
            'div.a3s.aiL',                             // Message body anywhere
            'div.ii.gt div.a3s',                       // Nested message body
            'div[data-message-id] div.a3s',            // Message with ID
            'div.nH.if div.a3s',                       // Alternative structure
            '.gs .ii .a3s',                            // Older Gmail structure
        ];
        
        let messageArea = null;
        let usedSelector = null;
        
        for (const selector of selectors) {
            messageArea = document.querySelector(selector);
            if (messageArea && messageArea.innerText.trim().length > 20) {
                usedSelector = selector;
                console.log("Found email body using selector:", selector);
                break;
            }
        }
        
        if (!messageArea) {
            console.error("Could not find email message area with any selector");
            console.log("Available elements:", {
                mainRole: !!document.querySelector('div[role="main"]'),
                a3sElements: document.querySelectorAll('.a3s').length,
                iiElements: document.querySelectorAll('.ii').length
            });
            sendResponse({ 
                success: false, 
                reason: "no-message-found", 
                error: "Email content not found in DOM. Try refreshing the page." 
            });
            return true;
        }
    
        const emailText = messageArea.innerText.trim();
        
        if (!emailText || emailText.length < 20) {
            console.error("Email text too short:", emailText.length, "chars");
            sendResponse({ 
                success: false, 
                reason: "text-too-short", 
                error: "Email content is too short or empty" 
            });
            return true;
        }
        
        console.log("Email extracted successfully:", emailText.length, "chars using", usedSelector);
        
        // Return the email text directly (background.js will handle AI processing)
        sendResponse({ success: true, text: emailText.slice(0, 8000) }); // limit for speed
        return true;
    }
    
    return true; // Keep channel open for async responses
});


// --- URL CHANGE WATCHER ---
console.log("Aegis One content script loaded and ready");

// Prevent multiple injections
if (window.aegisOneLoaded) {
    console.log("Aegis One already loaded, skipping duplicate injection");
} else {
    window.aegisOneLoaded = true;
    console.log("Aegis One initialized for the first time");
}

let lastUrl = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
        lastUrl = url;
        chrome.runtime.sendMessage({ type: "URL_CHANGED", url }).catch(() => {
            // Ignore errors if background script isn't listening
        });
    }
}).observe(document, { subtree: true, childList: true });
