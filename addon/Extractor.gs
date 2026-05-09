/**
 * Extracts all relevant data from the active Gmail message and formats it to
 * match the backend FastAPI EmailPayload schema.
 *
 * @param {Object} e - The event object passed by the Gmail Add-on trigger.
 * @returns {Object} The formatted payload ready to be sent to the backend.
 */
function extractEmailData(e) {
  const messageId = e.messageMetadata.messageId;
  const message = GmailApp.getMessageById(messageId);

  const rawContent = message.getRawContent();
  const returnPath = extractHeader(rawContent, 'Return-Path');
  const authResults = extractHeader(rawContent, 'Authentication-Results') || '';
  const replyTo = message.getReplyTo() || null;

  const processedAttachments = message.getAttachments().map(att => {
    const bytes = att.copyBlob().getBytes();
    const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
    const hexHash = digest.map(byte => {
      const unsignedByte = byte < 0 ? byte + 256 : byte;
      return unsignedByte.toString(16).padStart(2, '0');
    }).join('');
    return { filename: att.getName(), sha256: hexHash };
  });

  return {
    message_id: messageId,
    sender_address: message.getFrom(),
    return_path: returnPath,
    reply_to: replyTo,
    authentication_results: authResults,
    body_plain: message.getPlainBody().substring(0, 50000),
    body_html: message.getBody().substring(0, 150000),
    attachments: processedAttachments.slice(0, 20)
  };
}

/**
 * Extracts a named header value from raw email source text.
 *
 * @param {string} rawContent - The full raw source of the email.
 * @param {string} headerName - Header to find (e.g. 'Return-Path').
 * @returns {string|null} The header value, or null if not found.
 */
function extractHeader(rawContent, headerName) {
  const regex = new RegExp(`^${headerName}:\\s*(.+)$`, 'im');
  const match = rawContent.match(regex);
  if (match && match[1]) {
    return match[1].trim().replace(/^<|>$/g, '');
  }
  return null;
}
