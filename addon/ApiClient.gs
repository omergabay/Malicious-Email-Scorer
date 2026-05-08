function analyzeEmailWithBackend(payload) {
  const backendUrl = "https://unhelpful-deception-backshift.ngrok-free.dev/api/v1/analyze";
  
  const options = {
    'method': 'post',
    'contentType': 'application/json',
    'payload': JSON.stringify(payload),
    'muteHttpExceptions': true 
  };

  try {
    const response = UrlFetchApp.fetch(backendUrl, options);
    const responseCode = response.getResponseCode();
    const responseText = response.getContentText();

    if (responseCode !== 200) {
      throw new Error(`API Error (${responseCode}): ${responseText}`);
    }

    return JSON.parse(responseText);
  } catch (error) {
    // We throw the error up to Code.gs so it knows to trigger the Error UI
    throw new Error("Backend connection failed: " + error.message);
  }
}