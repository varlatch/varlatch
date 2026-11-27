// SPDX-License-Identifier: AGPL-3.0-or-later

/**
 * Reading a QR image in the browser, with the browser's own Barcode Detection
 * API: no dependency, and no image leaves the page. Where the API is missing
 * (Firefox and Safari have none, as of 2026) there is no reader, and a seed is
 * pasted.
 */

type Detector = { detect: (image: ImageBitmap) => Promise<{ rawValue: string }[]> };
type DetectorConstructor = new (options: { formats: string[] }) => Detector;

/** The reader, or null where the browser has none. It resolves to the first QR code's text, null for no code. */
export function qrReader(scope: object = globalThis): ((image: Blob) => Promise<string | null>) | null {
  const { BarcodeDetector, createImageBitmap: toBitmap } = scope as {
    BarcodeDetector?: DetectorConstructor;
    createImageBitmap?: (image: Blob) => Promise<ImageBitmap>;
  };
  if (!BarcodeDetector || !toBitmap) return null;
  return async (image) => {
    const bitmap = await toBitmap(image);
    try {
      const [code] = await new BarcodeDetector({ formats: ["qr_code"] }).detect(bitmap);
      return code?.rawValue ?? null;
    } finally {
      bitmap.close();
    }
  };
}
