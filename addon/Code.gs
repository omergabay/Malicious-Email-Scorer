function buildAddOn(e) {
  try {
    const payload = extractEmailData(e);
    const analysisResult = analyzeEmailWithBackend(payload);
    return buildAnalysisCard(analysisResult);
  } catch (error) {
    return buildErrorCard(error.message);
  }
}

function onRescan(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildAddOn(e)))
    .build();
}

function onMoveToSpam(e) {
  try {
    const messageId = e.messageMetadata.messageId;
    GmailApp.getMessageById(messageId).getThread().moveToSpam();
    return notify('Thread moved to Spam.');
  } catch (err) {
    return notify('Error: ' + err.message);
  }
}

function onMoveToTrash(e) {
  try {
    const messageId = e.messageMetadata.messageId;
    GmailApp.getMessageById(messageId).getThread().moveToTrash();
    return notify('Thread moved to Trash.');
  } catch (err) {
    return notify('Error: ' + err.message);
  }
}

function notify(text) {
  return CardService.newActionResponseBuilder()
    .setNotification(CardService.newNotification().setText(text))
    .build();
}
