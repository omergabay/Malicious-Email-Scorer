/**
 * The main entry point for the Gmail Add-on.
 */
function buildAddOn(e) {
  try {
    // 1. Extract
    const payload = extractEmailData(e);
    
    // 2. Analyze
    const analysisResult = analyzeEmailWithBackend(payload);
    
    // 3. Render
    return buildAnalysisCard(analysisResult);
    
  } catch (error) {
    // Catch any extraction or network errors and render the fallback UI
    return buildErrorCard(error.message);
  }
}