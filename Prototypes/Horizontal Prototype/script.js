function showResults(phishingText, llmText) {
  const phishingEl = document.getElementById("phishing-result");
  const llmEl = document.getElementById("llm-result");

  if (phishingEl) phishingEl.textContent = phishingText;
  if (llmEl) llmEl.textContent = llmText;
}

function checkDeterministically() {
  const phishingMsg = "80% Phishing";
  const llmMsg = "75% LLM Generated";

  console.log(phishingMsg);
  console.log(llmMsg);
  showResults(phishingMsg, llmMsg);
}

function checkWithAI() {
  const phishingMsg = "95% Phishing";
  const llmMsg = "97% LLM Generated";

  console.log(phishingMsg);
  console.log(llmMsg);
  showResults(phishingMsg, llmMsg);
}
