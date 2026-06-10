const API_BASE = 'http://localhost:8000';

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function phishingPercentFromResult(result) {
  if (result.phishing_probability != null) {
    return Math.round(result.phishing_probability * 100);
  }
  const score = result.prediction;
  if (typeof score === 'number') {
    return score <= 1 ? Math.round(score * 100) : Math.round(score);
  }
  return 0;
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function apiGet(path, params) {
  const url = new URL(`${API_BASE}${path}`);
  for (const [key, value] of Object.entries(params)) {
    url.searchParams.set(key, value);
  }

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  return response.json();
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function getAIEmailHumanPhishingPrediction(subject, body) {
  return apiGet('/predict-email-phishing-with-ai-human', { subject, body });
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function getAIEmailLLMPhishingPrediction(subject, body) {
  return apiGet('/predict-email-phishing-with-ai-llm', { subject, body });
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function getDeterministicEmailPrediction(subject, body) {
  return apiGet('/predict-email-phishing-with-deterministic', { subject, body });
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function detectLLMEmail(body) {
  return apiGet('/detect-llm-email', { body });
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
async function classifyEmail(subject, body, method = 'ai') {
  const llmPrediction = await detectLLMEmail(body);
  const llmPercent = phishingPercentFromResult(llmPrediction);

  let phishingResult;
  if (method === 'deterministic') {
    phishingResult = await getDeterministicEmailPrediction(subject, body);
  } else if (llmPrediction.llm_probability > 0.5) {
    phishingResult = await getAIEmailLLMPhishingPrediction(subject, body);
  } else {
    phishingResult = await getAIEmailHumanPhishingPrediction(subject, body);
  }

  return {
    phishingProbability: phishingPercentFromResult(phishingResult) / 100,
    llmProbability: llmPercent / 100,
    phishingResult,
    llmResult: llmPrediction,
  };
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
chrome.runtime.onMessage.addListener((message, sendResponse) => {
  if (message.action !== 'predict') return;

  const { subject, body, method = 'ai' } = message;
  const text = `${subject} ${body}`.trim();

  if (!text) {
    sendResponse({ success: false, error: 'subject/body cannot both be empty' });
    return;
  }

  classifyEmail(subject, body, method).then(({ phishingProbability, llmProbability }) => {
      chrome.storage.session.set({
        lastPhishingProbability: phishingProbability,
        lastLlmProbability: llmProbability,
        lastUpdated: Date.now(),
      });
      sendResponse({ success: true, phishingProbability, llmProbability });
    })
    .catch((err) => {
      console.error('[EmailClassifier] Prediction failed:', err);
      sendResponse({ success: false, error: err.message });
    });

  return true;
});
