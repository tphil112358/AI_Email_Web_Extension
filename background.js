chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "URL_CHANGED") {
        console.log("URL changed:", msg.url);
    }
});
