/**
 * Tamper a receipt by changing one field while preserving pretty JSON output.
 */
export function tamperReceiptJson(receiptJson) {
  const receipt = JSON.parse(receiptJson);

  if (typeof receipt.output === 'string') {
    receipt.output = `${receipt.output} [TAMPERED]`;
  } else if (receipt.output && typeof receipt.output === 'object') {
    receipt.output.tampered = true;
  } else {
    receipt.output = 'tampered-output';
  }

  return JSON.stringify(receipt, null, 2);
}
