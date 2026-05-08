/**
 * Extracts all relevant data from the active Gmail message and 
 * formats it to match the backend FastAPI EmailPayload schema.
 * * @param {Object} e - The event object passed by the Gmail Add-on trigger
 * @returns {Object} The formatted payload ready to be sent to the backend
 */
function extractEmailData(e) {
  // 1. Get the active message
  const messageId = e.messageMetadata.messageId;
  const message = GmailApp.getMessageById(messageId);
  
  // 2. Parse Raw Headers (Since .getHeader() doesn't exist natively)
  const rawContent = message.getRawContent();
  const returnPath = extractHeader(rawContent, 'Return-Path');
  const authResults = extractHeader(rawContent, 'Authentication-Results') || "";
  const replyTo = message.getReplyTo() || null;
  
  // 3. Process Attachments and compute SHA-256 Hashes
  const attachments = message.getAttachments();
  const processedAttachments = attachments.map(att => {
    // Get the raw bytes of the file
    const bytes = att.copyBlob().getBytes();
    
    // Compute the SHA-256 digest (Returns an array of signed bytes)
    const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
    
    // Convert the signed byte array into a clean 64-character Hex string
    const hexHash = digest.map(byte => {
      // Convert signed byte to unsigned, then to hex
      const unsignedByte = byte < 0 ? byte + 256 : byte;
      return unsignedByte.toString(16).padStart(2, '0');
    }).join('');
    
    return {
      filename: att.getName(),
      sha256: hexHash
    };
  });

  // 4. Construct the final payload matching our Pydantic schema
  const payload = {
    message_id: messageId,
    sender_address: message.getFrom(),
    return_path: returnPath,
    reply_to: replyTo,
    authentication_results: authResults,
    headers: {}, // Can populate with specific headers if needed later
    body_plain: message.getPlainBody().substring(0, 50000), // Enforce our backend hard caps
    body_html: message.getBody().substring(0, 150000),
    attachments: processedAttachments.slice(0, 20) // Enforce the 20 attachment cap
  };

  return payload;
}

/**
 * Helper function to extract specific headers from raw email source.
 * * @param {string} rawContent - The full raw source of the email
 * @param {string} headerName - The name of the header to find (e.g., 'Return-Path')
 * @returns {string|null} The header value, or null if not found
 */
function extractHeader(rawContent, headerName) {
  // Regex looks for the header at the start of a line, captures everything until the next line
  const regex = new RegExp(`^${headerName}:\\s*(.+)$`, 'im');
  const match = rawContent.match(regex);
  
  if (match && match[1]) {
    // Clean up any angle brackets often found in Return-Paths (e.g., <bounces@domain.com>)
    return match[1].trim().replace(/^<|>$/g, '');
  }
  return null;
}