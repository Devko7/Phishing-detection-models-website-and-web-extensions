//  Main writer: Jon Zdovc 
//  Reviewer: - 
//  Contributor: -

function normalizeUrlForModel(url) {
  return url.trim().replace(/^https?:\/\//i, "");
}

const API_URL = "http://localhost:8000/predict-url-phishing-with-ai";
// Added "1" in case the model returns binary numeric labels instead of strings
const MALICIOUS_LABELS = ["phishing", "defacement", "malware", "1"]; 

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // We only care about the main frame (top-level URL), ignore background iframes
  if (details.frameId !== 0) return;

  const url = details.url;

  // Ignore safe protocols and our own backend to prevent infinite loops
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('http://localhost')) {
    return;
  }

  try {
    const normalizedUrl = normalizeUrlForModel(url);
    const apiUrl = new URL(API_URL);
    apiUrl.searchParams.set("url", normalizedUrl);

    const response = await fetch(apiUrl.toString());
    const result = await response.json();

    console.log("Checking URL:", url, "| Normalized:", normalizedUrl, "| API Result:", result); 

    // Normalize the prediction label for checking
    const predictionLabel = String(result.prediction).toLowerCase();

    // Intercept and block if malicious
    if (MALICIOUS_LABELS.includes(predictionLabel)) {
      // Pass the bad URL as a query parameter so we can display it on the warning page
      const blockPageUrl = chrome.runtime.getURL("block.html") + "?blockedUrl=" + encodeURIComponent(url);
      chrome.tabs.update(details.tabId, { url: blockPageUrl });
    }
    // If benign, we do nothing and the connection proceeds naturally.

  } catch (error) {
    console.error("Phishing Detector API Error:", error);
    // If the server is offline, fail open (allow navigation) so browsing doesn't break entirely.
  }
});