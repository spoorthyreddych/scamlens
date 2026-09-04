/* =========================================================
   ScamLens — script.js
   Vanilla JavaScript only. No frameworks.

   PHASE 3 SCOPE:
   - Input type switching
   - Input capture (screenshot / message / url / email)
   - Client-side validation
   - Loading + investigation progress UI
   - Result rendering (score, level, category, evidence,
     suspicious text, recommendations, steps, limitations)
   - Error handling
   - Scan history (session-only, in-memory)

   NOT IN THIS PHASE:
   - No calls to FastAPI backend
   - No calls to Featherless AI
   - No API keys anywhere in this file (none should ever
     exist in frontend JS — keys stay server-side only)

   All investigation results in this phase come from
   clearly labeled MOCK data (see MOCK_RESULTS below) so we
   can verify rendering logic before the backend exists.
   Nothing here is presented as a real scan result to a user
   outside of development.
   ========================================================= */

(function () {
  "use strict";

  /* ---------------------------------------------------------
     0. STATE
     --------------------------------------------------------- */
  const state = {
    activeInputType: "screenshot", // 'screenshot' | 'message' | 'url' | 'email'
    screenshotFile: null,
    isInvestigating: false,
    scanHistory: [], // in-memory only, cleared on page reload
  };

  const INPUT_TYPES = ["screenshot", "message", "url", "email"];

  /* ---------------------------------------------------------
     1. DOM REFERENCES
     --------------------------------------------------------- */
  const dom = {
    // Input type selector
    typeButtons: {
      screenshot: document.getElementById("type-btn-screenshot"),
      message: document.getElementById("type-btn-message"),
      url: document.getElementById("type-btn-url"),
      email: document.getElementById("type-btn-email"),
    },
    panels: {
      screenshot: document.getElementById("panel-screenshot"),
      message: document.getElementById("panel-message"),
      url: document.getElementById("panel-url"),
      email: document.getElementById("panel-email"),
    },

    // Screenshot input
    screenshotDropzone: document.getElementById("screenshot-dropzone"),
    screenshotUpload: document.getElementById("screenshot-upload"),
    screenshotPreviewWrapper: document.getElementById("screenshot-preview-wrapper"),
    screenshotPreview: document.getElementById("screenshot-preview"),
    screenshotRemoveBtn: document.getElementById("screenshot-remove-btn"),
    dropzoneText: document.querySelector(".dropzone-text"),

    // Text inputs
    messageTextarea: document.getElementById("message-textarea"),
    urlInput: document.getElementById("url-input"),
    emailTextarea: document.getElementById("email-textarea"),

    // Action
    investigateBtn: document.getElementById("investigate-btn"),

    // Input section (used to attach validation error banner)
    inputSection: document.getElementById("input-section"),

    // Progress
    progressSection: document.getElementById("investigation-progress"),
    progressSteps: document.getElementById("progress-steps"),

    // Result
    resultSection: document.getElementById("result-section"),
    riskScoreValue: document.getElementById("risk-score-value"),
    riskLevelBadge: document.getElementById("risk-level-badge"),
    riskLevelText: document.getElementById("risk-level-text"),
    scamCategoryValue: document.getElementById("scam-category-value"),
    evidenceList: document.getElementById("evidence-list"),
    detectedSignalsList: document.getElementById("detected-signals-list"),
    suspiciousTextValue: document.getElementById("suspicious-text-value"),
    extractedUrlsList: document.getElementById("extracted-urls-list"),
    investigationStepsList: document.getElementById("investigation-steps-list"),
    confidenceValue: document.getElementById("confidence-value"),
    limitationsValue: document.getElementById("limitations-value"),
    recommendationsList: document.getElementById("recommendations-list"),
    showInvestigation: document.getElementById("show-investigation"),

    // Scan history
    scanHistoryList: document.getElementById("scan-history-list"),
    scanHistoryEmpty: document.getElementById("scan-history-empty"),
  };

  /* ---------------------------------------------------------
     2. PIPELINE STEP LABELS
     Mirrors the required architecture:
     INPUT -> EXTRACTION -> INDEPENDENT ANALYSIS ->
     EVIDENCE AGGREGATION -> RISK ENGINE -> AI INTERPRETATION ->
     DECISION -> ACTION
     These are UI-only labels for the progress timeline in
     this phase; the real backend will drive real step
     statuses once connected.
     --------------------------------------------------------- */
  const PIPELINE_STEPS = [
    { id: "extraction", label: "Extracting content" },
    { id: "text-analysis", label: "Analyzing text signals" },
    { id: "url-analysis", label: "Analyzing URLs" },
    { id: "evidence-aggregation", label: "Aggregating evidence" },
    { id: "risk-engine", label: "Calculating risk score" },
    { id: "ai-interpretation", label: "Interpreting findings" },
    { id: "decision", label: "Finalizing decision" },
  ];

  /* ---------------------------------------------------------
     3. MOCK DATA (DEVELOPMENT ONLY)
     Clearly labeled. Used only to verify rendering logic
     before the backend/AI pipeline exists. This is never
     presented as a live scan — it is only reachable via the
     Investigate button in this phase, and every place it is
     used is annotated MOCK.
     --------------------------------------------------------- */
  const MOCK_RESULTS = {
    low: {
      risk_score: 12,
      risk_level: "low",
      scam_category: "No significant scam indicators detected",
      detected_signals: ["no-urgency-language", "no-suspicious-links", "known-domain"],
      evidence: [
        "No urgency or threat language detected in the text.",
        "No suspicious or shortened URLs found.",
        "Sender domain matches a recognized organization pattern.",
      ],
      suspicious_text: "(none flagged)",
      extracted_urls: ["https://example.com/account/settings"],
      recommendations: [
        "No immediate action required.",
        "Continue to verify sender identity for sensitive requests.",
      ],
      investigation_steps: [
        "Extracted text content from input.",
        "Ran independent text signal analysis — no red flags.",
        "Ran independent URL analysis — domain reputation normal.",
        "Aggregated evidence from all modules.",
        "Deterministic risk engine calculated a low risk score.",
        "AI interpretation layer summarized findings.",
      ],
      confidence: "High (0.88)",
      limitations: "This is MOCK development data, not a real investigation result.",
    },
    medium: {
      risk_score: 48,
      risk_level: "medium",
      scam_category: "Possible phishing attempt",
      detected_signals: ["urgency-language", "generic-greeting", "link-mismatch"],
      evidence: [
        "Message uses urgency language such as 'act now' or 'immediately'.",
        "Generic greeting used instead of a personalized name.",
        "Displayed link text does not match the underlying URL destination.",
      ],
      suspicious_text: "\"Your account will be suspended within 24 hours unless you verify now.\"",
      extracted_urls: ["https://secure-verify-account.example-login.net/verify"],
      recommendations: [
        "Do not click the link directly from this message.",
        "Navigate to the official website manually to check your account status.",
        "Report the message to your email provider.",
      ],
      investigation_steps: [
        "Extracted text and links from input.",
        "Independent text analysis flagged urgency language.",
        "Independent URL analysis flagged a link/destination mismatch.",
        "Aggregated evidence from all modules.",
        "Deterministic risk engine calculated a medium risk score.",
        "AI interpretation layer explained the evidence in plain language.",
      ],
      confidence: "Medium (0.67)",
      limitations: "This is MOCK development data, not a real investigation result.",
    },
    high: {
      risk_score: 74,
      risk_level: "high",
      scam_category: "Credential phishing (likely)",
      detected_signals: [
        "urgency-language",
        "lookalike-domain",
        "request-for-credentials",
        "poor-grammar",
      ],
      evidence: [
        "Domain closely mimics a well-known brand with subtle misspelling.",
        "Message explicitly requests login credentials or payment details.",
        "Multiple grammar and spelling irregularities detected.",
        "High-pressure urgency language detected in multiple sentences.",
      ],
      suspicious_text: "\"We detected unusual activity. Confirm your password and card number now to avoid permanent suspension.\"",
      extracted_urls: ["http://paypa1-secure-login.com/confirm"],
      recommendations: [
        "Do not enter any credentials or payment information.",
        "Do not click any links in this message.",
        "Report and delete the message immediately.",
        "If you already entered credentials, change your password immediately on the official site.",
      ],
      investigation_steps: [
        "Extracted text and links from input.",
        "Independent text analysis flagged high-risk language patterns.",
        "Independent URL analysis flagged a lookalike domain.",
        "Aggregated evidence from all modules.",
        "Deterministic risk engine calculated a high risk score.",
        "AI interpretation layer explained the evidence in plain language.",
      ],
      confidence: "High (0.91)",
      limitations: "This is MOCK development data, not a real investigation result.",
    },
    critical: {
      risk_score: 93,
      risk_level: "critical",
      scam_category: "Active credential/financial scam",
      detected_signals: [
        "urgency-language",
        "lookalike-domain",
        "request-for-credentials",
        "request-for-payment",
        "known-scam-pattern",
      ],
      evidence: [
        "URL matches a known scam pattern structure seen in prior reports.",
        "Message requests both login credentials and immediate payment.",
        "Extreme urgency and threat language detected throughout.",
        "Domain registered recently and unrelated to the claimed sender.",
      ],
      suspicious_text: "\"FINAL NOTICE: Pay $499 within 1 hour or legal action will be taken. Click below and enter your card details to resolve immediately.\"",
      extracted_urls: ["http://irs-gov-payment-portal.tk/pay-now"],
      recommendations: [
        "Do not click any links or provide any information.",
        "Do not make any payment.",
        "Report this to the relevant authority or platform immediately.",
        "Block the sender.",
      ],
      investigation_steps: [
        "Extracted text and links from input.",
        "Independent text analysis flagged severe threat/urgency language.",
        "Independent URL analysis flagged a known scam domain pattern.",
        "Aggregated evidence from all modules.",
        "Deterministic risk engine calculated a critical risk score.",
        "AI interpretation layer explained the evidence in plain language.",
      ],
      confidence: "High (0.95)",
      limitations: "This is MOCK development data, not a real investigation result.",
    },
  };

  /* ---------------------------------------------------------
     4. INPUT TYPE SWITCHING
     --------------------------------------------------------- */
  function setActiveInputType(type) {
    if (!INPUT_TYPES.includes(type)) return;

    state.activeInputType = type;

    INPUT_TYPES.forEach((t) => {
      const btn = dom.typeButtons[t];
      const panel = dom.panels[t];
      const isActive = t === type;

      btn.classList.toggle("active", isActive);
      btn.setAttribute("aria-selected", isActive ? "true" : "false");
      panel.hidden = !isActive;
    });

    clearValidationError();
  }

  function initInputTypeSwitching() {
    INPUT_TYPES.forEach((t) => {
      dom.typeButtons[t].addEventListener("click", () => setActiveInputType(t));
    });
  }

  /* ---------------------------------------------------------
     5. SCREENSHOT FILE SELECTION
     --------------------------------------------------------- */
  function handleScreenshotFile(file) {
    if (!file) return;

    if (!file.type.startsWith("image/")) {
      showValidationError("Please select a valid image file.");
      return;
    }

    const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10MB
    if (file.size > MAX_SIZE_BYTES) {
      showValidationError("Image is too large. Please select a file under 10MB.");
      return;
    }

    state.screenshotFile = file;
    clearValidationError();

    const reader = new FileReader();
    reader.onload = (e) => {
      dom.screenshotPreview.src = e.target.result;
      dom.screenshotPreviewWrapper.hidden = false;
      dom.dropzoneText.hidden = true;
    };
    reader.readAsDataURL(file);
  }

  function clearScreenshotFile() {
    state.screenshotFile = null;
    dom.screenshotUpload.value = "";
    dom.screenshotPreview.src = "";
    dom.screenshotPreviewWrapper.hidden = true;
    dom.dropzoneText.hidden = false;
  }

  function initScreenshotInput() {
    dom.screenshotUpload.addEventListener("change", (e) => {
      const file = e.target.files && e.target.files[0];
      handleScreenshotFile(file);
    });

    dom.screenshotRemoveBtn.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      clearScreenshotFile();
    });

    // Drag and drop
    ["dragenter", "dragover"].forEach((evtName) => {
      dom.screenshotDropzone.addEventListener(evtName, (e) => {
        e.preventDefault();
        dom.screenshotDropzone.classList.add("dragover");
      });
    });

    ["dragleave", "drop"].forEach((evtName) => {
      dom.screenshotDropzone.addEventListener(evtName, (e) => {
        e.preventDefault();
        dom.screenshotDropzone.classList.remove("dragover");
      });
    });

    dom.screenshotDropzone.addEventListener("drop", (e) => {
      const file = e.dataTransfer.files && e.dataTransfer.files[0];
      handleScreenshotFile(file);
    });
  }

  /* ---------------------------------------------------------
     6. VALIDATION
     --------------------------------------------------------- */
  function showValidationError(message) {
    clearValidationError();
    const errorEl = document.createElement("div");
    errorEl.id = "validation-error";
    errorEl.className = "error-state";
    errorEl.textContent = message;
    errorEl.setAttribute("role", "alert");
    dom.inputSection.appendChild(errorEl);
  }

  function clearValidationError() {
    const existing = document.getElementById("validation-error");
    if (existing) existing.remove();
  }

  function validateInput() {
    const type = state.activeInputType;

    if (type === "screenshot") {
      if (!state.screenshotFile) {
        showValidationError("Please upload a screenshot to investigate.");
        return false;
      }
      return true;
    }

    if (type === "message") {
      const value = dom.messageTextarea.value.trim();
      if (value.length < 3) {
        showValidationError("Please paste a message to investigate.");
        return false;
      }
      return true;
    }

    if (type === "url") {
      const value = dom.urlInput.value.trim();
      if (!value) {
        showValidationError("Please enter a URL to investigate.");
        return false;
      }
      try {
        // Basic well-formedness check only. Never fetches the URL.
        new URL(value);
      } catch (err) {
        showValidationError("Please enter a valid URL (including https://).");
        return false;
      }
      return true;
    }

    if (type === "email") {
      const value = dom.emailTextarea.value.trim();
      if (value.length < 3) {
        showValidationError("Please paste the email content to investigate.");
        return false;
      }
      return true;
    }

    return false;
  }

  /* ---------------------------------------------------------
     7. LOADING STATE + INVESTIGATION PROGRESS UI
     --------------------------------------------------------- */
  function setInvestigateButtonLoading(isLoading) {
    dom.investigateBtn.disabled = isLoading;
    dom.investigateBtn.textContent = isLoading ? "Investigating..." : "Investigate";
  }

  function renderProgressSteps() {
    dom.progressSteps.innerHTML = "";
    PIPELINE_STEPS.forEach((step) => {
      const li = document.createElement("li");
      li.className = "progress-step pending";
      li.id = `progress-step-${step.id}`;
      li.textContent = step.label;
      dom.progressSteps.appendChild(li);
    });
  }

  function setStepStatus(stepId, status) {
    const el = document.getElementById(`progress-step-${stepId}`);
    if (!el) return;
    el.classList.remove("pending", "active", "done", "error");
    el.classList.add(status);
  }

  function showProgressSection() {
    dom.progressSection.hidden = false;
    dom.resultSection.hidden = true;
  }

  function hideProgressSection() {
    dom.progressSection.hidden = true;
  }

  /**
   * Simulates the investigation pipeline progressing through each
   * step for UI/timing verification purposes only.
   * DEVELOPMENT ONLY — the real implementation will update step
   * statuses based on actual backend responses, not timers.
   */
  function simulateProgressSteps(onComplete) {
    let index = 0;

    function advance() {
      if (index > 0) {
        setStepStatus(PIPELINE_STEPS[index - 1].id, "done");
      }
      if (index >= PIPELINE_STEPS.length) {
        onComplete();
        return;
      }
      setStepStatus(PIPELINE_STEPS[index].id, "active");
      index += 1;
      setTimeout(advance, 350);
    }

    advance();
  }

  /* ---------------------------------------------------------
     8. RESULT RENDERING FUNCTIONS
     --------------------------------------------------------- */
  function renderRiskScore(score) {
    dom.riskScoreValue.textContent = typeof score === "number" ? score : "--";
  }

  function renderRiskLevel(level) {
    const normalized = (level || "unknown").toLowerCase();
    dom.riskLevelBadge.setAttribute("data-level", normalized);
    dom.riskLevelBadge.classList.remove("low", "medium", "high", "critical");
    if (["low", "medium", "high", "critical"].includes(normalized)) {
      dom.riskLevelBadge.classList.add(normalized);
    }
    dom.riskLevelText.textContent = normalized.charAt(0).toUpperCase() + normalized.slice(1);
  }

  function renderScamCategory(category) {
    dom.scamCategoryValue.textContent = category || "Not determined";
  }

  function renderEvidence(evidenceArray) {
    dom.evidenceList.innerHTML = "";
    if (!evidenceArray || evidenceArray.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No specific evidence was recorded.";
      dom.evidenceList.appendChild(li);
      return;
    }
    evidenceArray.forEach((item) => {
      const li = document.createElement("li");
      li.className = "evidence-item";
      li.textContent = item;
      dom.evidenceList.appendChild(li);
    });
  }

  function renderDetectedSignals(signalsArray) {
    dom.detectedSignalsList.innerHTML = "";
    if (!signalsArray || signalsArray.length === 0) {
      const li = document.createElement("li");
      li.textContent = "None detected.";
      dom.detectedSignalsList.appendChild(li);
      return;
    }
    signalsArray.forEach((signal) => {
      const li = document.createElement("li");
      li.textContent = signal;
      dom.detectedSignalsList.appendChild(li);
    });
  }

  function renderSuspiciousText(text) {
    dom.suspiciousTextValue.textContent = text && text.trim() ? text : "(none flagged)";
  }

  function renderExtractedUrls(urlsArray) {
    dom.extractedUrlsList.innerHTML = "";
    if (!urlsArray || urlsArray.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No URLs were found in the input.";
      dom.extractedUrlsList.appendChild(li);
      return;
    }
    urlsArray.forEach((url) => {
      const li = document.createElement("li");
      li.textContent = url;
      dom.extractedUrlsList.appendChild(li);
    });
  }

  function renderRecommendations(recommendationsArray) {
    dom.recommendationsList.innerHTML = "";
    if (!recommendationsArray || recommendationsArray.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No specific recommendations available.";
      dom.recommendationsList.appendChild(li);
      return;
    }
    recommendationsArray.forEach((rec) => {
      const li = document.createElement("li");
      li.className = "recommendation-card";
      li.textContent = rec;
      dom.recommendationsList.appendChild(li);
    });
  }

  function renderInvestigationSteps(stepsArray) {
    dom.investigationStepsList.innerHTML = "";
    if (!stepsArray || stepsArray.length === 0) {
      const li = document.createElement("li");
      li.textContent = "No investigation steps were recorded.";
      dom.investigationStepsList.appendChild(li);
      return;
    }
    stepsArray.forEach((step) => {
      const li = document.createElement("li");
      li.textContent = step;
      dom.investigationStepsList.appendChild(li);
    });
  }

  function renderConfidence(confidence) {
    dom.confidenceValue.textContent = confidence || "Not available";
  }

  function renderLimitations(limitations) {
    dom.limitationsValue.textContent = limitations || "No limitations recorded.";
  }

  /**
   * Renders a full result object into the result section.
   * Expected shape matches the documented final result contract:
   * risk_score, risk_level, scam_category, detected_signals,
   * evidence, suspicious_text, extracted_urls, recommendations,
   * investigation_steps, confidence, limitations.
   */
  function renderResult(result) {
    renderRiskScore(result.risk_score);
    renderRiskLevel(result.risk_level);
    renderScamCategory(result.scam_category);
    renderEvidence(result.evidence);
    renderDetectedSignals(result.detected_signals);
    renderSuspiciousText(result.suspicious_text);
    renderExtractedUrls(result.extracted_urls);
    renderRecommendations(result.recommendations);
    renderInvestigationSteps(result.investigation_steps);
    renderConfidence(result.confidence);
    renderLimitations(result.limitations);

    dom.showInvestigation.open = false;
    dom.resultSection.hidden = false;
  }

  /* ---------------------------------------------------------
     9. ERROR HANDLING
     --------------------------------------------------------- */
  function showInvestigationError(message) {
    hideProgressSection();
    dom.resultSection.hidden = true;

    clearInvestigationError();
    const errorEl = document.createElement("div");
    errorEl.id = "investigation-error";
    errorEl.className = "error-state";
    errorEl.setAttribute("role", "alert");
    errorEl.textContent = message;
    dom.inputSection.appendChild(errorEl);
  }

  function clearInvestigationError() {
    const existing = document.getElementById("investigation-error");
    if (existing) existing.remove();
  }

  /* ---------------------------------------------------------
     10. SCAN HISTORY (session-only, in-memory)
     --------------------------------------------------------- */
  function addToScanHistory(inputType, result) {
    const entry = {
      inputType,
      riskLevel: result.risk_level,
      riskScore: result.risk_score,
      category: result.scam_category,
      timestamp: new Date(),
    };
    state.scanHistory.unshift(entry);
    renderScanHistory();
  }

  function renderScanHistory() {
    dom.scanHistoryList.innerHTML = "";

    if (state.scanHistory.length === 0) {
      const li = document.createElement("li");
      li.id = "scan-history-empty";
      li.className = "scan-history-empty";
      li.textContent = "No scans yet.";
      dom.scanHistoryList.appendChild(li);
      return;
    }

    state.scanHistory.forEach((entry) => {
      const li = document.createElement("li");
      li.className = "scan-history-item";

      const typeSpan = document.createElement("span");
      typeSpan.className = "history-input-type";
      typeSpan.textContent = entry.inputType;

      const snippetSpan = document.createElement("span");
      snippetSpan.className = "history-snippet";
      snippetSpan.textContent = entry.category;

      const badgeSpan = document.createElement("span");
      badgeSpan.className = `history-badge ${entry.riskLevel}`;
      badgeSpan.textContent = `${entry.riskLevel} (${entry.riskScore})`;

      li.appendChild(typeSpan);
      li.appendChild(snippetSpan);
      li.appendChild(badgeSpan);
      dom.scanHistoryList.appendChild(li);
    });
  }

  /* ---------------------------------------------------------
     11. MOCK INVESTIGATION RUNNER (DEVELOPMENT ONLY)
     Picks a mock result based on simple, transparent rules so
     testers can trigger each risk level deterministically.
     THIS FUNCTION MUST BE REPLACED in a later phase with a real
     fetch() call to the FastAPI backend. It performs NO network
     request and NO real AI call.
     --------------------------------------------------------- */
  function getMockResultForCurrentInput() {
    const type = state.activeInputType;
    let text = "";

    if (type === "message") text = dom.messageTextarea.value;
    else if (type === "url") text = dom.urlInput.value;
    else if (type === "email") text = dom.emailTextarea.value;
    else if (type === "screenshot") text = state.screenshotFile ? state.screenshotFile.name : "";

    const lower = text.toLowerCase();

    // Simple, transparent keyword routing so testers can force each
    // risk level while verifying rendering. NOT scam detection logic.
    if (lower.includes("critical")) return MOCK_RESULTS.critical;
    if (lower.includes("high")) return MOCK_RESULTS.high;
    if (lower.includes("medium")) return MOCK_RESULTS.medium;
    if (lower.includes("low")) return MOCK_RESULTS.low;

    // Default mock outcome when no keyword is present.
    return MOCK_RESULTS.medium;
  }

  function runMockInvestigation() {
    if (state.isInvestigating) return;
    if (!validateInput()) return;

    clearInvestigationError();
    state.isInvestigating = true;
    setInvestigateButtonLoading(true);

    renderProgressSteps();
    showProgressSection();

    simulateProgressSteps(() => {
      try {
        // MOCK DATA — replace with real backend response in a later phase.
        const result = getMockResultForCurrentInput();

        hideProgressSection();
        renderResult(result);
        addToScanHistory(state.activeInputType, result);
      } catch (err) {
        showInvestigationError(
          "Something went wrong while rendering the investigation result."
        );
      } finally {
        state.isInvestigating = false;
        setInvestigateButtonLoading(false);
      }
    });
  }

  /* ---------------------------------------------------------
     12. INIT
     --------------------------------------------------------- */
  function init() {
    initInputTypeSwitching();
    initScreenshotInput();
    setActiveInputType(state.activeInputType);
    renderScanHistory();

    dom.investigateBtn.addEventListener("click", runMockInvestigation);
  }

  document.addEventListener("DOMContentLoaded", init);
})();