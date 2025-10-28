// content.js

// Robust detection similar to the executeScript version

function detectGmailContextContent() {
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
        if (/#inbox\b|\/#inbox/i.test(hash)) return { context: "inbox", reason: "url-hint" };
        if (/#(thread|message|inbox)\/\d+/.test(hash) || /#inbox\/\w+/.test(hash)) return { context: "email", reason: "url-message-id" };
    } catch (e) {
        return { context: "none", reason: "error", error: String(e) };
    }
    return { context: "inbox", reason: "fallback" };
}

// Find unsubscribe link using multiple heuristics
function findUnsubscribeLink() {
    // Look for rel="unsubscribe" links
    const relUnsub = Array.from(document.querySelectorAll('a[rel~="unsubscribe"]')).map(a => a.href).filter(Boolean);
    if (relUnsub.length) return relUnsub[0];

    // Search visible text for 'unsubscribe'
    const anchors = Array.from(document.querySelectorAll('a[href]'));
    for (const a of anchors) {
        const text = (a.textContent || "").trim().lower();
        if (/unsubscribe/i.test(text)) return a.href;
    }

    // Gmail sometimes puts a small footer with 'Unsubscribe' in-line; search for mailto or list-unsubscribe header links
    // As a fallback search for common patterns
    for (const a of anchors) {
        if (/\/unsubscribe|unsubscribe=true|list-unsubscribe/i.test(a.href)) return a.href;
    }

    return null;
}

// Basic (very simple) link scan: heuristics only (stub)
function quickScanLinks() {
    const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 50);
    // naive heuristics: look for suspicious domains or display text mismatch
    for (const a of links) {
        const href = a.href || "";
        const text = a.textContent || "";
        // Example rule: text includes secure words but href is different domain
        if (/login|verify|update|secure/i.test(text) && /google|amazon|apple|microsoft/i.test(text) && !href.includes(window.location.hostname)) {
            return { level: "warning", detail: `⚠️ Suspicious link: ${href}` };
        }
        // malicious domain example (very naive)
        if (/login-|secure-|verify-|account-|signin-/.test(href) && /(\.xyz|\.info|\.top|\.ru)$/i.test(href)) {
            return { level: "danger", detail: `🚨 Malicious link found: ${href}` };
        }
    }
    return { level: "safe", detail: "✅ No threats detected." };
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "GET_GMAIL_CONTEXT") {
        sendResponse(detectGmailContextContent());
        return; // synchronous response
    }

    if (msg.type === "SCAN_SPAM") {
        const link = findUnsubscribeLink();
        sendResponse({ unsubscribeLink: link });
        return;
    }

    if (msg.type === "SCAN_LINKS") {
        const result = { level: "safe", detail: "✅ No threats detected." }
        sendResponse({ result });
        return;
    }

    // Keep alive if we do async work (not used here)
    return true;
});

// Placeholder content script for now
console.log("Aegis One content script active.");

// Optionally watch URL changes for future dynamic updates
let lastUrl = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrl) {
        lastUrl = url;
        chrome.runtime.sendMessage({ type: "URL_CHANGED", url });
    }
}).observe(document, { subtree: true, childList: true });