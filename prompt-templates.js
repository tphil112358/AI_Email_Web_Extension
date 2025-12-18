// Prompt Engineering Templates for Aegis One
// Uses few-shot learning and meta-fielding for consistent AI outputs

/**
 * Generate a well-engineered prompt for email summarization
 * @param {string} emailText - The email content to summarize
 * @returns {string} - Engineered prompt with examples
 */
function generateSummarizationPrompt(emailText) {
    return `You are an expert email analyzer. Your task is to analyze emails and provide structured summaries.

OUTPUT FORMAT (Required):
Generate a summary in the following JSON structure:
{
  "summary": "Brief 1-2 sentence overview",
  "key_points": ["point 1", "point 2", "point 3"],
  "action_items": ["action 1", "action 2"] or [],
  "sentiment": "positive" | "neutral" | "negative",
  "urgency": "low" | "medium" | "high",
  "category": "work" | "personal" | "marketing" | "notification" | "other"
}

FEW-SHOT EXAMPLES:

Example 1:
Email: "Hi team, our Q4 presentation is due next Friday. Please submit your slides by Wednesday so I can compile them. Let me know if you need any help. Thanks!"

Output:
{
  "summary": "Q4 presentation deadline reminder with submission request by Wednesday.",
  "key_points": ["Q4 presentation due next Friday", "Individual slides due Wednesday", "Offer of help available"],
  "action_items": ["Submit slides by Wednesday", "Request help if needed"],
  "sentiment": "positive",
  "urgency": "high",
  "category": "work"
}

Example 2:
Email: "Your order #12345 has shipped! Track your package here: [link]. Expected delivery: Dec 15-18. Thanks for shopping with us!"

Output:
{
  "summary": "Order confirmation and shipping notification with tracking information.",
  "key_points": ["Order #12345 shipped", "Tracking link provided", "Delivery expected Dec 15-18"],
  "action_items": [],
  "sentiment": "positive",
  "urgency": "low",
  "category": "notification"
}

Example 3:
Email: "URGENT: Your account shows suspicious activity. Click here immediately to verify your identity and prevent account closure. Act within 24 hours!"

Output:
{
  "summary": "Urgent security alert claiming suspicious account activity requiring immediate verification.",
  "key_points": ["Claims suspicious activity detected", "Requests immediate action", "Threatens account closure", "24-hour deadline mentioned"],
  "action_items": [],
  "sentiment": "negative",
  "urgency": "high",
  "category": "other"
}

NOW ANALYZE THIS EMAIL:

Email:
${emailText}

Output (JSON only, no additional text):`;
}

/**
 * Generate a prompt for phishing/threat analysis
 * @param {Array} links - Array of {href, text} objects
 * @param {string} emailContext - Brief email context
 * @returns {string} - Engineered prompt for threat detection
 */
function generateThreatAnalysisPrompt(links, emailContext) {
    const linksText = links.map((link, i) => 
        `Link ${i + 1}: text="${link.text}" href="${link.href}"`
    ).join('\n');

    return `You are a cybersecurity expert specializing in phishing detection. Analyze these email links for potential threats.

OUTPUT FORMAT (Required):
{
  "threat_level": "safe" | "warning" | "danger",
  "confidence": 0.0 to 1.0,
  "suspicious_links": [
    {
      "link_index": number,
      "reason": "explanation",
      "indicators": ["indicator1", "indicator2"]
    }
  ],
  "overall_assessment": "brief explanation"
}

DETECTION CRITERIA:
1. Text-URL mismatch (text says "google.com" but links elsewhere)
2. Suspicious domains (look-alikes, unusual TLDs, randomized subdomains)
3. Urgency language combined with sensitive actions
4. Shortened URLs hiding real destination
5. Login/credential requests from unexpected sources
6. Homograph attacks (unicode lookalikes)

FEW-SHOT EXAMPLES:

Example 1:
Context: "Password reset notification from your bank"
Links:
Link 1: text="Reset Password" href="https://secure.bankofamerica.com/reset"
Link 2: text="Contact Support" href="https://bankofamerica.com/help"

Output:
{
  "threat_level": "safe",
  "confidence": 0.95,
  "suspicious_links": [],
  "overall_assessment": "All links point to legitimate Bank of America domains with proper HTTPS. No text-URL mismatches detected."
}

Example 2:
Context: "Urgent security alert"
Links:
Link 1: text="Verify Account at PayPal" href="https://paypal-secure-verify.tk/login"
Link 2: text="paypal.com/security" href="http://bit.ly/2xK9mP"

Output:
{
  "threat_level": "danger",
  "confidence": 0.98,
  "suspicious_links": [
    {
      "link_index": 1,
      "reason": "Text claims PayPal but links to suspicious domain with unusual TLD (.tk)",
      "indicators": ["text-URL mismatch", "suspicious TLD", "fake subdomain pattern"]
    },
    {
      "link_index": 2,
      "reason": "Text shows PayPal domain but uses URL shortener to hide real destination",
      "indicators": ["URL shortener", "potential redirect", "HTTP not HTTPS"]
    }
  ],
  "overall_assessment": "High-confidence phishing attempt. Both links are deceptive and lead away from legitimate PayPal domains."
}

NOW ANALYZE THESE LINKS:

Context: ${emailContext}

Links:
${linksText}

Output (JSON only, no additional text):`;
}

/**
 * Parse JSON response from AI, with fallback handling
 * @param {string} response - AI response text
 * @returns {object} - Parsed JSON or error object
 */
function parseAIResponse(response) {
    try {
        // Try to extract JSON from response (in case AI adds text before/after)
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[0]);
        }
        
        // If no JSON found, try parsing entire response
        return JSON.parse(response);
    } catch (error) {
        console.error("Failed to parse AI response:", error);
        return {
            error: true,
            message: "Could not parse AI response",
            raw: response
        };
    }
}

// Export functions
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        generateSummarizationPrompt,
        generateThreatAnalysisPrompt,
        parseAIResponse
    };
}
