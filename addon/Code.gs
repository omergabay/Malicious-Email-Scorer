function buildAddOn(e) {
  // Use the specific ngrok URL you provided
  const backendUrl = "https://unhelpful-deception-backshift.ngrok-free.dev/api/v1/analyze";
  
  // Dummy payload following the Pydantic EmailPayload schema
  const payload = {
    "message_id": "demo_test_id_123",
    "sender_address": "test@upwind-demo.com",
    "return_path": "test@upwind-demo.com",
    "headers": {},
    "body_plain": "Hello, this is a test for the Upwind Home Assignment.",
    "body_html": "<p>Hello, this is a test for the Upwind Home Assignment.</p>",
    "attachment_hashes": []
  };

  const options = {
    'method': 'post',
    'contentType': 'application/json',
    'payload': JSON.stringify(payload),
    'muteHttpExceptions': true
  };

  try {
    const response = UrlFetchApp.fetch(backendUrl, options);
    const jsonResponse = JSON.parse(response.getContentText());

    // Build the UI card as required by the task [cite: 21]
    const card = CardService.newCardBuilder();
    const section = CardService.newCardSection()
      .addWidget(CardService.newDecoratedText()
        .setText("<b>Connection Status:</b> SUCCESS")
        .setBottomLabel("Backend is reachable via ngrok"))
      .addWidget(CardService.newDecoratedText()
        .setTopLabel("Score")
        .setText(jsonResponse.total_score.toString()))
      .addWidget(CardService.newDecoratedText()
        .setTopLabel("Verdict")
        .setText(jsonResponse.overall_verdict))
      .addWidget(CardService.newTextParagraph()
        .setText("<b>Reasoning:</b> " + jsonResponse.heuristics[0].details));
      
    return card.addSection(section).build();

  } catch (error) {
    const errorCard = CardService.newCardBuilder();
    errorCard.addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText("<b>Backend Connection Failed:</b> " + error.toString())));
    return errorCard.build();
  }
}