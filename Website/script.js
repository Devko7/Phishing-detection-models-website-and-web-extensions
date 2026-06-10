const subjectInput = document.getElementById("email-subject-input");
const bodyInput = document.getElementById("email-body-input");
const urlInput = document.getElementById("url-input");

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
function scoreToColor(value) {
  const clamped = Math.max(0, Math.min(100, value));
  const hue = (1 - clamped / 100) * 120; // 0 = green, 120 = red
  return `hsl(${hue}, 80%, 45%)`;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
function updateBar(barId, value) {
  const bar = document.getElementById(barId);
  const clamped = Math.max(0, Math.min(100, value));
  bar.style.width = clamped + "%";
  bar.style.backgroundColor = scoreToColor(clamped);
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
function phishingPercentFromResult(result) {
  if (result.phishing_probability != null) {
    return Math.round(result.phishing_probability * 100);
  }
  const score = result.prediction;
  if (typeof score === "number") {
    return score <= 1 ? Math.round(score * 100) : Math.round(score);
  }
  return 0;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
function returnResults(phishingPrediction, llmPrediction) {
  const phishingResult = document.getElementById("phishing-result");
  const llmResult = document.getElementById("llm-result");

  phishingResult.textContent = phishingPrediction;
  llmResult.textContent = llmPrediction;

  updateBar("phishing-bar", phishingPrediction);
  updateBar("llm-bar", llmPrediction);
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function checkDeterministically() {
  let result;
  let llmDisplayPercent;
  const llmPrediction = await detectLLMEmail(bodyInput.value);

  if (urlInput.value && !subjectInput.value && !bodyInput.value) {
    result = await getDeterministicURLPrediction(urlInput.value);
    llmDisplayPercent = "Not applicable";

  } else if (subjectInput.value && bodyInput.value && !urlInput.value) {
    const subject = subjectInput.value;
    const body = bodyInput.value;
    result = await getDeterministicEmailPrediction(subject, body);
    llmDisplayPercent = phishingPercentFromResult(llmPrediction);

  } else if (urlInput.value && subjectInput.value && bodyInput.value) {
    warningElement = document.getElementById("warning-text");
    warningElement.textContent = "Please enter ONLY an email or a URL";
    return;

  } else {
    warningElement = document.getElementById("warning-text");
    warningElement.textContent = "Please enter either a URL or email";
    return;
  }

  const phishingPrediction = phishingPercentFromResult(result);

  returnResults(phishingPrediction, llmDisplayPercent);
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function checkWithAI() {
  let result;
  let llmDisplayPercent;
  const llmPrediction = await detectLLMEmail(bodyInput.value);

  if (urlInput.value && !subjectInput.value && !bodyInput.value) {
    result = await getAIURLPrediction(urlInput.value);
    llmDisplayPercent = "Not applicable";

  } else if (subjectInput.value && bodyInput.value && !urlInput.value) {
    const subject = subjectInput.value;
    const body = bodyInput.value;
    llmDisplayPercent = phishingPercentFromResult(llmPrediction);

    // If the LLM detector is confident above 50% that the email is LLM-generated, use the LLM phishing detection model, otherwise use the human phishing detection model.
    if (llmPrediction.llm_probability > 0.5) {
      result = await getAIEmailLLMPhishingPrediction(subject, body);
    } else {
      result = await getAIEmailHumanPhishingPrediction(subject, body);
    }
  } else if (urlInput.value && subjectInput.value && bodyInput.value) {
    warningElement = document.getElementById("warning-text");
    warningElement.textContent = "Please enter ONLY an email or a URL";
    return;

  } else {
    warningElement = document.getElementById("warning-text");
    warningElement.textContent = "Please enter either a URL or email";
    return;
  }

  const phishingPrediction = phishingPercentFromResult(result);

  returnResults(phishingPrediction, llmDisplayPercent);
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function getAIEmailHumanPhishingPrediction(subject, body) {
  const apiUrl = new URL("http://localhost:8000/predict-email-phishing-with-ai-human");

  apiUrl.searchParams.set("subject", subject);
  apiUrl.searchParams.set("body", body);
  
  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function getAIEmailLLMPhishingPrediction(subject, body) {
  const apiUrl = new URL("http://localhost:8000/predict-email-phishing-with-ai-llm");

  apiUrl.searchParams.set("subject", subject);
  apiUrl.searchParams.set("body", body);
  
  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function getAIURLPrediction(url) {
  const apiUrl = new URL("http://localhost:8000/predict-url-phishing-with-ai");

  apiUrl.searchParams.set("url", url);
  
  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function getDeterministicEmailPrediction(subject, body) {
  const apiUrl = new URL("http://localhost:8000/predict-email-phishing-with-deterministic");

  apiUrl.searchParams.set("subject", subject);
  apiUrl.searchParams.set("body", body);
  
  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: Shaked Gayer
async function getDeterministicURLPrediction(url) {
  const apiUrl = new URL("http://localhost:8000/predict-url-phishing-with-deterministic");

  apiUrl.searchParams.set("url", url);

  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}

// Main writer: David Vasilev
// Reviewer: Theodotos Neokleous
// Contributor: -
async function detectLLMEmail(body) {
  const apiUrl = new URL("http://localhost:8000/detect-llm-email");

  apiUrl.searchParams.set("body", body);
  
  const response = await fetch(apiUrl);
  const data = await response.json();
  return data;
}