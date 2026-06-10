const phishingCard = document.getElementById('phishing-card');
const phishingScoreEl = document.getElementById('phishing-score');
const phishingBarEl = document.getElementById('phishing-bar');
const phishingVerdict = document.getElementById('phishing-verdict');
const llmCard = document.getElementById('llm-card');
const llmScoreEl = document.getElementById('llm-score');
const llmBarEl = document.getElementById('llm-bar');
const llmVerdict = document.getElementById('llm-verdict');
const statusEl = document.getElementById('status');
const tsEl = document.getElementById('timestamp');

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function getColor(pct) {
  if (pct >= 70) return '#ff003c';
  if (pct >= 40) return '#f5a623';
  return '#00ff61';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function getPhishingVerdict(pct) {
  if (pct >= 70) return 'High risk — likely phishing';
  if (pct >= 40) return 'Moderate — treat with caution';
  return 'Looks clean';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function getLlmVerdict(pct) {
  if (pct >= 70) return 'Likely AI-generated';
  if (pct >= 40) return 'Possibly AI-generated';
  return 'Likely human-written';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function renderMetric({ card, scoreEl, barEl, verdictEl, probability, verdictFn }) {
  const pct = Math.round(probability * 100);
  const color = getColor(pct);

  scoreEl.innerHTML = `${pct}<span class="score-unit">%</span>`;
  setTimeout(() => { barEl.style.width = `${pct}%`; }, 50);
  verdictEl.textContent = verdictFn(pct);
  card.style.setProperty('--accent-color', color);
  barEl.style.background = color;
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function render(phishingProbability, llmProbability, lastUpdated) {
  renderMetric({
    card: phishingCard,
    scoreEl: phishingScoreEl,
    barEl: phishingBarEl,
    verdictEl: phishingVerdict,
    probability: phishingProbability,
    verdictFn: getPhishingVerdict,
  });

  renderMetric({
    card: llmCard,
    scoreEl: llmScoreEl,
    barEl: llmBarEl,
    verdictEl: llmVerdict,
    probability: llmProbability,
    verdictFn: getLlmVerdict,
  });

  statusEl.textContent = 'Last analysed email:';

  // Timestamp
  if (lastUpdated) {
    const d = new Date(lastUpdated);
    tsEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function renderEmpty() {
  phishingScoreEl.textContent = '—';
  phishingVerdict.textContent = 'No data yet';
  phishingBarEl.style.width = '0%';
  llmScoreEl.textContent = '—';
  llmVerdict.textContent = 'No data yet';
  llmBarEl.style.width = '0%';
  statusEl.textContent = 'Open an email in Gmail to analyse it.';
  tsEl.textContent = '';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function renderError() {
  phishingScoreEl.textContent = 'ERR';
  phishingVerdict.textContent = 'API call failed';
  llmScoreEl.textContent = 'ERR';
  llmVerdict.textContent = 'API call failed';
  statusEl.textContent = 'Check console for details.';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
chrome.storage.session.get(['lastPhishingProbability', 'lastLlmProbability', 'lastUpdated'], (data) => {
  if (chrome.runtime.lastError) {
    renderError();
    return;
  }

  if (data.lastPhishingProbability !== undefined && data.lastPhishingProbability !== null) {
    render(data.lastPhishingProbability, data.lastLlmProbability ?? 0, data.lastUpdated);
  } else {
    renderEmpty();
  }
});
