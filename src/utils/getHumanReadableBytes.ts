/**
 * Converts bytes to human readable format with appropriate units
 *
 * @param bytes - Size in bytes to convert
 * @param decimals - Number of decimal places to show (default: 2)
 * @returns String representation of size with unit (e.g., "1.50 MB")
 * @description
 * - Handles edge case where bytes is 0 or negative
 * - Automatically selects appropriate unit (Bytes, KB, MB, GB, etc.)
 * - Uses base-1024 conversion for binary units
 * - Rounds to specified number of decimal places
 */
export const getHumanReadableBytes = (bytes: number, decimals = 2) => {
  if (bytes <= 0) return "0 Bytes";

  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB", "TB", "PB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  return parseFloat((bytes / Math.pow(k, i)).toFixed(decimals)) + " " + sizes[i];
};
