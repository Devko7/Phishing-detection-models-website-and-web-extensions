const BADGE_ID = 'email-classifier-badge';
const INTER_FONT_ID = 'email-classifier-inter-font';

function ensureInterFont() {
  if (document.getElementById(INTER_FONT_ID)) return;

  const link = document.createElement('link');
  link.id = INTER_FONT_ID;
  link.rel = 'stylesheet';
  link.href = 'https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap';
  document.head.appendChild(link);
}

// Selectors for the email body and subject for Gmail
const BODY_SELECTORS = [
  '.a3s.aiL',
  '.ii.gt',
  '[data-message-id] .a3s',
];

const SUBJECT_SELECTORS = [
  'h2.hP',
  '.ha .hP',
  '[data-thread-perm-id] h2',
];

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function getEmailBody() {
  for (const selector of BODY_SELECTORS) {
    const el = document.querySelector(selector);
    if (el && el.innerText.trim()) return el.innerText.trim();
  }
  return '';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function getEmailSubject() {
  for (const selector of SUBJECT_SELECTORS) {
    const el = document.querySelector(selector);
    if (el && el.innerText.trim()) return el.innerText.trim();
  }
  return '';
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function removeBadge() {
  const existing = document.getElementById(BADGE_ID);
  if (existing) existing.remove();
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function showBadge(state, phishingProbability = null, llmProbability = null) {
  ensureInterFont();
  removeBadge();

  const badge = document.createElement('div');
  badge.id = BADGE_ID;

  const phishingPct = phishingProbability !== null ? Math.round(phishingProbability * 100) : null;
  const llmPct = llmProbability !== null ? Math.round(llmProbability * 100) : null;
  const color = phishingPct === null ? '#888' : phishingPct >= 70 ? '#e94560' : phishingPct >= 40 ? '#f5a623' : '#2ecc71';

  let label;
  if (state === 'loading') {
    label = 'Checking email…';
  } else if (state === 'error') {
    label = 'Classifier error';
  } else {
    label = `Phishing: <strong style="color:${color}">${phishingPct}%</strong>`;
    if (llmPct !== null) {
      label += ` · LLM: <strong>${llmPct}%</strong>`;
    }
  }

  badge.innerHTML = label;

  Object.assign(badge.style, {
    position:     'fixed',
    bottom:       '24px',
    right:        '24px',
    background:   '#000000',
    color:        '#ffffff',
    padding:      '10px 18px',
    borderRadius: '10px',
    fontSize:     '13px',
    fontFamily:   "'Inter', sans-serif",
    zIndex:       '2147483647',
    transition:   'opacity 0.3s ease',
    opacity:      '0',
  });

  document.body.appendChild(badge);
  requestAnimationFrame(() => { badge.style.opacity = '1'; });

  setTimeout(() => {
    badge.style.opacity = '0';
    setTimeout(removeBadge, 300);
  }, 8000);
}

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
function classifyCurrentEmail() {
  const subject = getEmailSubject();
  const body = getEmailBody();
  if (!subject && !body) return;

  showBadge('loading');

  chrome.runtime.sendMessage({ action: 'predict', subject, body }, (response) => {
    if (chrome.runtime.lastError) {
      console.error('[EmailClassifier]', chrome.runtime.lastError.message);
      showBadge('error');
      return;
    }
    if (response?.success) {
      showBadge('result', response.phishingProbability, response.llmProbability);
    } else {
      showBadge('error');
    }
  });
}

let lastEmailKey = null;

// Main writer: David Vasilev
// Reviewer: Sidra Al Khawam
// Contributor: -
const observer = new MutationObserver(() => {
  const subject = getEmailSubject();
  const body = getEmailBody();
  const key = `${subject}::${body}`;
  if ((subject || body) && key !== lastEmailKey) {
    lastEmailKey = key;
    classifyCurrentEmail();
  }
});

observer.observe(document.body, { childList: true, subtree: true });
