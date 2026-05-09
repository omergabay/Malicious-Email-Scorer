// Cached within a single execution to avoid repeated PropertiesService round-trips.
let _backendUrl = null;

/**
 * Posts the email payload to the backend and returns the parsed analysis result.
 *
 * The backend URL is read once from Script Properties (key: BACKEND_URL) and cached
 * for the duration of the execution. Update it in the Apps Script UI without touching code.
 *
 * @param {Object} payload - The formatted email payload from extractEmailData().
 * @returns {Object} Parsed AnalysisResponse from the backend.
 * @throws {Error} If BACKEND_URL is not configured or the API call fails.
 */
function analyzeEmailWithBackend(payload) {
  if (!_backendUrl) {
    _backendUrl = PropertiesService.getScriptProperties().getProperty('BACKEND_URL');
  }
  if (!_backendUrl) throw new Error('BACKEND_URL is not set in Script Properties.');

  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };

  try {
    const response = UrlFetchApp.fetch(_backendUrl + '/api/v1/analyze', options);
    const responseCode = response.getResponseCode();
    const responseText = response.getContentText();

    if (responseCode !== 200) {
      throw new Error(`API Error (${responseCode}): ${responseText}`);
    }

    return JSON.parse(responseText);
  } catch (error) {
    throw new Error('Backend connection failed: ' + error.message);
  }
}
