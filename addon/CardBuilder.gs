const BRAND = {
  name:    'Malicious Email Scorer',
  safe:    '#1a7f37',
  warn:    '#bf8700',
  danger:  '#cf222e',
  muted:   '#57606a',
  surface: '#f6f8fa'
};

/**
 * Builds the full analysis card shown inside Gmail.
 *
 * @param {Object} r - The AnalysisResponse object from the backend.
 * @returns {Card} The rendered Gmail Add-on card.
 */
function buildAnalysisCard(r) {
  const verdict = r.verdict || 'Unknown';
  const score   = r.total_score || 0;
  const tone    = verdictTone(verdict);

  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(BRAND.name)
      .setSubtitle('Threat analysis complete')
      .setImageUrl('https://www.gstatic.com/images/icons/material/system/1x/security_white_48dp.png')
      .setImageStyle(CardService.ImageStyle.CIRCLE))
    .setPeekCardHeader(CardService.newCardHeader()
      .setTitle(`${verdict} • ${score}/100`)
      .setImageUrl(tone.icon));

  card.addSection(buildVerdictSection(verdict, score, tone));

  if ((r.analyst_report || []).length) {
    card.addSection(buildInsightsSection(r.analyst_report));
  }

  card.addSection(buildBreakdownSection(r.analysis || {}));
  card.addSection(buildActionsSection(r));

  card.setFixedFooter(CardService.newFixedFooter()
    .setPrimaryButton(CardService.newTextButton()
      .setText('Re-scan')
      .setOnClickAction(CardService.newAction().setFunctionName('onRescan'))));

  return card.build();
}

/**
 * Builds the verdict hero section showing the score bar and verdict label.
 *
 * @param {string} verdict - 'Safe', 'Suspicious', or 'Malicious'.
 * @param {number} score - Aggregate threat score 0–100.
 * @param {Object} tone - Color/icon/subtitle object from verdictTone().
 * @returns {CardSection}
 */
function buildVerdictSection(verdict, score, tone) {
  const bar = scoreBar(score, tone.color);
  return CardService.newCardSection()
    .addWidget(CardService.newDecoratedText()
      .setStartIcon(CardService.newIconImage().setIconUrl(tone.icon))
      .setTopLabel('Verdict')
      .setText(`<b><font color="${tone.color}">${verdict.toUpperCase()}</font></b>`)
      .setBottomLabel(tone.subtitle)
      .setWrapText(true))
    .addWidget(CardService.newTextParagraph().setText(
      `<b>Threat score</b><br>` +
      `<font color="${BRAND.muted}">${bar}</font> ` +
      `<b><font color="${tone.color}">${score}</font></b><font color="${BRAND.muted}">/100</font>`));
}

/**
 * Renders a 20-block ASCII progress bar colored by verdict.
 *
 * @param {number} score - Score 0–100.
 * @param {string} color - Hex color for filled blocks.
 * @returns {string} HTML string.
 */
function scoreBar(score, color) {
  const filled = Math.round((score / 100) * 20);
  return `<font color="${color}">${'█'.repeat(filled)}</font>` +
         `<font color="#d0d7de">${'█'.repeat(20 - filled)}</font>`;
}

/**
 * Returns color, subtitle text, and icon URL for a given verdict string.
 *
 * @param {string} v - 'Malicious', 'Suspicious', or anything else (Safe).
 * @returns {{color: string, subtitle: string, icon: string}}
 */
function verdictTone(v) {
  if (v === 'Malicious')  return { color: BRAND.danger, subtitle: 'Do not interact with this email', icon: 'https://fonts.gstatic.com/s/i/short-term/release/materialsymbols/dangerous/default/24px.svg' };
  if (v === 'Suspicious') return { color: BRAND.warn,   subtitle: 'Treat with caution',              icon: 'https://fonts.gstatic.com/s/i/short-term/release/materialsymbols/warning/default/24px.svg' };
  return                       { color: BRAND.safe,   subtitle: 'No threats detected',              icon: 'https://fonts.gstatic.com/s/i/short-term/release/materialsymbols/verified/default/24px.svg' };
}

/**
 * Builds the analyst insights section from the list of report strings.
 *
 * @param {string[]} reports - HTML-formatted finding strings from the backend.
 * @returns {CardSection}
 */
function buildInsightsSection(reports) {
  const section = CardService.newCardSection()
    .setHeader('Key findings')
    .setCollapsible(false);

  reports.slice(0, 5).forEach(r => {
    section.addWidget(CardService.newDecoratedText()
      .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.DESCRIPTION))
      .setText('&#x200E;' + r)
      .setWrapText(true));
  });

  return section;
}

/**
 * Builds the collapsible heuristic breakdown section.
 *
 * @param {Object} analysis - Keyed heuristic result dicts from the backend.
 * @returns {CardSection}
 */
function buildBreakdownSection(analysis) {
  const section = CardService.newCardSection()
    .setHeader('Detailed checks')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);

  const labels = {
    sender_identity:      'Sender identity',
    social_engineering:   'Social engineering',
    link_target_mismatch: 'Links',
    attachment_scan:      'Attachments'
  };

  Object.keys(analysis).forEach(name => {
    const d = analysis[name] || {};
    const score = d.score || 0;
    const triggered = countTriggered(name, d);
    const total = countTotal(name);
    // Math.max guards against triggered > total if new signals are added later
    const passed = Math.max(0, total - triggered);
    const tone = triggered === 0 ? BRAND.safe : (triggered <= 1 ? BRAND.warn : BRAND.danger);
    const iconKey = triggered === 0 ? CardService.Icon.STAR : CardService.Icon.DESCRIPTION;

    section.addWidget(CardService.newDecoratedText()
      .setStartIcon(CardService.newIconImage().setIcon(iconKey))
      .setTopLabel(labels[name] || name)
      .setText(`<b><font color="${tone}">${passed}/${total} passed</font></b>`)
      .setBottomLabel(`Risk contribution: ${score}`)
      .setWrapText(true));

    const specificDetails = getSpecificDetailsText(name, d);
    if (specificDetails) {
      section.addWidget(CardService.newTextParagraph().setText(specificDetails));
    }
  });

  return section;
}

/**
 * Extracts specific evidence strings (domains, links, keywords, filenames) for a heuristic result.
 *
 * @param {string} name - Heuristic key (e.g. 'sender_identity').
 * @param {Object} d - Heuristic detail dict.
 * @returns {string|null} HTML-formatted bullet list, or null if nothing to show.
 */
function getSpecificDetailsText(name, d) {
  const lines = [];
  const add = (text) => lines.push(`&#x200E;  • ${text}`);

  if (name === 'sender_identity') {
    if (d.domain_mismatch && (d.score || 0) > 0) {
      add(`<b>Spoofing:</b> 'From' (${d.domains?.from || 'unknown'}) masks real path (${d.domains?.return_path || 'unknown'})`);
    }
    if (d.reply_mismatch && (d.score || 0) > 0) {
      add(`<b>Reply Route:</b> Replies go to unexpected domain (${d.domains?.reply_to || 'unknown'})`);
    }
    if (d.auth_failed) add('<b>Auth:</b> SPF/DKIM validation failed');
    if (d.return_path_reputation === 'malicious') add(`<b>Reputation:</b> VT flagged domain (${d.domains?.return_path || d.domains?.from})`);

  } else if (name === 'social_engineering') {
    if (d.categories_triggered && Object.keys(d.categories_triggered).length > 0) {
      Object.entries(d.categories_triggered).forEach(([cat, words]) => {
        const cleanCat = cat.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
        if (words && words.length > 0) {
          add(`<b>${cleanCat}:</b> "${words.join(', ')}"`);
        }
      });
    }

  } else if (name === 'link_target_mismatch') {
    if (d.mismatch_found && d.mismatched_links && d.mismatched_links.length > 0) {
      d.mismatched_links.slice(0, 3).forEach(ex => {
        add(`<b>Deception:</b> '${ex.display.substring(0, 20)}...' → '${ex.actual_href.substring(0, 30)}...'`);
      });
      if (d.mismatched_links.length > 3) add(`<i>...and ${d.mismatched_links.length - 3} more</i>`);
    }
    if (d.is_shortener && d.shortener_domains && d.shortener_domains.length > 0) {
      add(`<b>Obfuscation:</b> Shorteners used (${d.shortener_domains.join(', ')})`);
    } else if (d.is_shortener) {
      add('<b>Obfuscation:</b> Uses link shortener');
    }
    if (d.malicious_domains && d.malicious_domains.length > 0) {
      add(`<b>Malware:</b> VT flagged domains: ${d.malicious_domains.join(', ')}`);
    }

  } else if (name === 'attachment_scan') {
    if (d.malicious_files && d.malicious_files.length > 0) {
      add(`<b>Malware:</b> VT flagged file(s): ${d.malicious_files.join(', ')}`);
    }
    if (d.findings) {
      d.findings.forEach(f => {
        if (f.is_double_extension) add(`<b>Double Ext:</b> '${f.filename}'`);
        if (f.is_dangerous) add(`<b>Dangerous Type:</b> '${f.filename}'`);
      });
    }
  }

  return lines.length > 0 ? `<font color="${BRAND.muted}">${lines.join('<br>')}</font>` : null;
}

/**
 * Returns the total number of checkpoints evaluated for a given heuristic.
 *
 * @param {string} name - Heuristic key.
 * @returns {number}
 */
function countTotal(name) {
  return ({ sender_identity: 4, social_engineering: 2, link_target_mismatch: 3, attachment_scan: 3 })[name] || 0;
}

/**
 * Counts how many checkpoints were triggered (failed) for a given heuristic result.
 *
 * @param {string} name - Heuristic key.
 * @param {Object} d - Heuristic detail dict.
 * @returns {number}
 */
function countTriggered(name, d) {
  let n = 0;
  if (name === 'sender_identity') {
    if (d.auth_failed) n++;
    if (d.domain_mismatch && (d.score || 0) > 0) n++;
    if (d.reply_mismatch) n++;
    if (d.return_path_reputation === 'malicious') n++;
  } else if (name === 'social_engineering') {
    if (d.categories_triggered && d.categories_triggered['account_takeover_urgency']) n++;
    if (d.categories_triggered && Object.keys(d.categories_triggered).length > 0) n++;
  } else if (name === 'link_target_mismatch') {
    if (d.is_shortener) n++;
    if (d.mismatch_found) n++;
    if ((d.vt_malicious_hits || 0) >= 3) n++;
  } else if (name === 'attachment_scan') {
    if ((d.vt_malicious_hits || 0) > 0) n++;
    if ((d.findings || []).some(f => f.is_double_extension)) n++;
    if ((d.findings || []).some(f => f.is_dangerous)) n++;
  }
  return n;
}

/**
 * Builds the action buttons section (Move to Spam / Move to Trash).
 *
 * @returns {CardSection}
 */
function buildActionsSection() {
  const set = CardService.newButtonSet()
    .addButton(CardService.newTextButton()
      .setText('Move to Spam')
      .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
      .setBackgroundColor(BRAND.danger)
      .setOnClickAction(CardService.newAction().setFunctionName('onMoveToSpam')))
    .addButton(CardService.newTextButton()
      .setText('Move to Trash')
      .setOnClickAction(CardService.newAction().setFunctionName('onMoveToTrash')));

  return CardService.newCardSection().addWidget(set);
}

/**
 * Builds an error card shown when analysis fails.
 *
 * @param {string} errorMessage - Human-readable error description.
 * @returns {Card}
 */
function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle(BRAND.name)
      .setSubtitle('Analysis unavailable'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
        .setStartIcon(CardService.newIconImage().setIcon(CardService.Icon.DESCRIPTION))
        .setText("<b>We couldn't scan this email</b>")
        .setBottomLabel(errorMessage)
        .setWrapText(true))
      .addWidget(CardService.newTextButton()
        .setText('Try again')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName('buildAddOn'))))
    .build();
}
