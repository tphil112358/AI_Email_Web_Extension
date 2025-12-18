# Aegis One  
**AI-Powered Email Security & Productivity Extension**

---

## Overview

Aegis One is a Chrome browser extension designed to enhance email security and productivity for Gmail users. It combines AI-driven summarization with practical cybersecurity tooling, all while prioritizing user control and transparency. The extension operates directly within the Gmail interface and provides on-demand analysis without permanently storing user data.

Aegis One is built as an individual senior project for CSE 499 and demonstrates applied skills in browser extension development, AI integration, and secure client-side architecture.

---

## Core Features

### 1. Email Summarization (AI-Powered)
- Summarize individual emails on demand
- Summarize the inbox using recent emails (up to 50 messages within the last 7 days)
- Uses a configurable AI backend (currently Groq)
- Generates structured summaries including urgency, key points, and action items

### 2. Phishing & Malicious Link Detection
- Scans links inside opened emails
- Flags suspicious URLs based on heuristics:
  - Domain spoofing
  - Suspicious top-level domains
  - URL shorteners
  - HTTPS validation
- Displays color-coded threat indicators (safe / warning / danger)

### 3. Spam & Unsubscribe Detection
- Detects unsubscribe links embedded in email content
- Reveals unsubscribe URLs without auto-navigation
- Opens unsubscribe links in a new browser tab on user confirmation
- Designed to reduce unwanted email clutter safely

---

## How It Works

Aegis One follows a modular Chrome Extension architecture using Manifest V3:

- **Popup UI (`popup.html / popup.js`)**
  - User-facing controls
  - Displays summaries, threat indicators, and actions

- **Content Scripts (`content.js`)**
  - Runs inside Gmail tabs
  - Scrapes visible email and inbox data
  - Detects phishing indicators and unsubscribe links

- **Background Service Worker (`background.js`)**
  - Orchestrates communication between popup and content scripts
  - Builds AI prompts
  - Sends requests to the configured AI provider
  - Returns structured results to the UI

- **Settings Page**
  - Allows configuration of AI provider (Groq)
  - Manages API keys and feature toggles

All communication between components is handled using Chrome’s message-passing APIs. No email data is stored persistently by the extension.

---

## Data & Privacy Model

- Email content is only accessed when the user explicitly triggers a feature
- No emails or metadata are stored locally or remotely
- AI requests send only the minimum required data to the user-configured AI provider
- No third-party analytics or tracking is used
- Designed to comply with Chrome Web Store privacy requirements

---

## Installation Instructions

### Option 1: Chrome Web Store (Recommended)
1. Visit the Chrome Web Store listing for Aegis One
2. Click **Add to Chrome**
3. Confirm permissions
4. Navigate to Gmail and open the extension from the toolbar

### Option 2: Manual Installation (Developer Mode)
1. Clone or download the project repository
2. Open Chrome and navigate to `chrome://extensions`
3. Enable **Developer mode** (top right)
4. Click **Load unpacked**
5. Select the project directory
6. Open Gmail and pin the extension for easy access

---

## Usage Instructions

1. Open **Gmail** in Chrome
2. Click the **Aegis One** icon in the toolbar
3. Depending on context:
   - **Summarize Email** appears when viewing a single message
   - **Summarize Inbox** appears when viewing the inbox
4. Use **Scan for Threats** to analyze links in an email
5. Use **Scan for Spam** to detect unsubscribe options
6. View summaries, alerts, and actions directly in the popup

---

## Permissions Explained

Aegis One requests permissions to:
- Access Gmail tabs (`mail.google.com`)
- Read visible page content (required for email analysis)
- Open new tabs (for unsubscribe links)

These permissions are necessary for the extension’s functionality and are only used when explicitly triggered by the user.

---

## Technologies Used

- JavaScript (ES6+)
- Chrome Extensions API (Manifest V3)
- HTML / CSS
- Groq API (LLM backend)
- Gmail DOM heuristics
- Chrome runtime messaging

---

## Limitations

- Only emails currently visible in the Gmail UI can be analyzed
- Inbox summaries are best-effort based on loaded messages
- Heuristic-based phishing detection may produce false positives
- Performance depends on Gmail’s dynamic loading behavior

---

## Future Improvements

- Additional AI providers
- Improved inbox pagination handling
- Machine-learning–based phishing classification
- Enhanced spam categorization rules
- Cross-browser support

---

## Author

**Tyler Phillips**  
CSE 499 – Senior Project  
Brigham Young University–Idaho

---

## License

This project is intended for educational and demonstration purposes.  
No warranty is provided.

