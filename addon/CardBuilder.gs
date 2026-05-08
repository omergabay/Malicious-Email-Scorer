/**
 * Builds the main results UI with a detailed breakdown of the findings.
 * @param {Object} jsonResponse - The parsed JSON from the FastAPI backend.
 * @returns {CardService.Card} The constructed UI card.
 */
function buildAnalysisCard(jsonResponse) {
  const card = CardService.newCardBuilder();
  
  // --- Section 1: Summary Dashboard ---
  const summarySection = CardService.newCardSection()
    .setHeader("Analysis Summary")
    .addWidget(CardService.newDecoratedText()
      .setTopLabel("Threat Score")
      .setText("<b>&#x200E;" + jsonResponse.total_score.toString() + " / 100</b>")
      .setWrapText(true))
    .addWidget(CardService.newDecoratedText()
      .setTopLabel("Final Verdict")
      .setText(getVerdictStyled(jsonResponse.verdict)));

  // --- Section 2: Detailed Audit Log ---
  const detailSection = CardService.newCardSection().setHeader("Heuristic Breakdown");
  
  const analysis = jsonResponse.analysis;
  let findingsFound = false;

  for (let heuristicName in analysis) {
    const details = analysis[heuristicName];
    const reasoningHTML = getHumanReadableReasoning(heuristicName, details);
    
    if (reasoningHTML) {
      detailSection.addWidget(CardService.newTextParagraph().setText(reasoningHTML));
      findingsFound = true;
    }
  }

  if (!findingsFound) {
    detailSection.addWidget(CardService.newTextParagraph()
      .setText("<i>No telemetry available for this email.</i>"));
  }

  return card
    .addSection(summarySection)
    .addSection(detailSection)
    .build();
}

/**
 * Maps technical backend flags to a detailed Audit Log showing Passed vs Triggered.
 */
function getHumanReadableReasoning(name, details) {
  const hScore = details.score || 0;
  let flagged = [];
  let passed = [];
  let totalTests = 0;

  // We MUST inject &#x200E; at the start of every single line so the browser 
  // knows the line is English, keeping bullets and punctuation on the correct side.
  function evaluateTest(isTriggered, flaggedMsg, passedMsg) {
    totalTests++;
    if (isTriggered) {
      flagged.push("&#x200E;• " + flaggedMsg);
    } else {
      passed.push("&#x200E;• " + passedMsg);
    }
  }

  // --- 1. Sender Identity Checks ---
  if (name === "sender_identity") {
    evaluateTest(details.auth_failed, "<b>Auth Failed:</b> SPF/DKIM missing/invalid.", "<b>Auth:</b> Signatures valid.");
    
    const isSpoofing = details.domain_mismatch && hScore > 0;
    evaluateTest(isSpoofing, "<b>Spoofing:</b> 'From' doesn't match 'Return-Path'.", "<b>Identity:</b> Domain source verified.");
    evaluateTest(details.reply_mismatch, "<b>Reply Route:</b> Routed to different domain.", "<b>Routing:</b> Reply-To matches sender.");
    
    const rep = details.return_path_reputation || "unknown";
    evaluateTest(rep === "malicious", `<b>VirusTotal:</b> Sender domain flagged as ${rep}.`, `<b>VirusTotal:</b> Sender domain reputation is ${rep}.`);
  } 
  
  // --- 2. Social Engineering Checks ---
  else if (name === "social_engineering") {
    evaluateTest(details.urgency_detected, "<b>Urgency:</b> High-pressure language detected.", "<b>Tone:</b> No artificial urgency.");
    evaluateTest(details.action_words_found && details.action_words_found.length > 0, "<b>Call to Action:</b> High-risk phrases found.", "<b>Call to Action:</b> No suspicious requests.");
  } 
  
  // --- 3. Link Target Mismatch Checks ---
  else if (name === "link_target_mismatch") {
    evaluateTest(details.is_shortener, "<b>Obfuscation:</b> Link shortener used.", "<b>Transparency:</b> No shortened links.");
    evaluateTest(details.mismatch_found, "<b>Deception:</b> Visible text hides true destination.", "<b>Integrity:</b> Visible links match destinations.");
    
    const linkVtHits = details.vt_malicious_hits || 0;
    evaluateTest(linkVtHits >= 3, `<b>VirusTotal:</b> ${linkVtHits} vendors flagged links as malicious.`, `<b>VirusTotal:</b> 0 security engines flagged the links.`);
  } 
  
  // --- 4. Attachment Scan Checks ---
  else if (name === "attachment_scan") {
    const attVtHits = details.vt_malicious_hits || 0;
    evaluateTest(attVtHits > 0, `<b>VirusTotal:</b> ${attVtHits} vendors flagged attachment as malware.`, `<b>VirusTotal:</b> 0 security engines flagged the attachment.`);
    
    let hasDoubleExt = false;
    let hasDangerous = false;
    if (details.findings && details.findings.length > 0) {
      hasDoubleExt = details.findings.some(f => f.is_double_extension);
      hasDangerous = details.findings.some(f => f.is_dangerous);
    }
    
    evaluateTest(hasDoubleExt, "<b>Deception:</b> Hidden double extension found.", "<b>Extensions:</b> Standard file formats used.");
    evaluateTest(hasDangerous, "<b>Dangerous Type:</b> Executable/high-risk file found.", "<b>File Types:</b> Generally safe formats.");
  }

  // --- UI Formatting ---
  if (totalTests === 0) return null;

  const passRate = Math.round((passed.length / totalTests) * 100);
  const title = name.toUpperCase().replace(/_/g, ' ');
  
  // Injecting &#x200E; into every header and line break
  let html = `&#x200E;<b>${title}</b> (Score: ${hScore})<br>`;
  
  let rateColor = passRate === 100 ? '#27ae60' : (passRate >= 50 ? '#f1c40f' : '#ba0000');
  html += `&#x200E;Pass Rate: <font color='${rateColor}'><b>${passRate}%</b></font> (${passed.length}/${totalTests} tests)<br><br>`;

  if (flagged.length > 0) {
    html += `&#x200E;<font color='#ba0000'><b>⚠️ TRIGGERED:</b></font><br>` + flagged.join("<br>") + `<br><br>`;
  }
  
  if (passed.length > 0) {
    html += `&#x200E;<font color='#27ae60'><b>✅ PASSED:</b></font><br>` + passed.join("<br>") + `<br>`;
  }

  return html + `<br>`;
}

/**
 * Adds color-coding to the verdict text.
 */
function getVerdictStyled(verdict) {
  // FIX: Adding LRM here as well to protect the styling block
  if (verdict === "Malicious") return "&#x200E;<b><font color='#ba0000'>MALICIOUS</font></b>";
  if (verdict === "Suspicious") return "&#x200E;<b><font color='#f1c40f'>SUSPICIOUS</font></b>";
  return "&#x200E;<b><font color='#27ae60'>SAFE</font></b>";
}

/**
 * Standardized error UI.
 */
function buildErrorCard(errorMessage) {
  const errorCard = CardService.newCardBuilder();
  errorCard.addSection(CardService.newCardSection()
    .addWidget(CardService.newTextParagraph()
      .setText("&#x200E;<b><font color='#ba0000'>System Error</font></b><br>" + errorMessage)));
  return errorCard.build();
}