// SPDX-License-Identifier: AGPL-3.0-or-later
/** The Varlatch mark: light mark on dark surfaces, dark mark on light ones. */
export function BrandMark({ size = 24 }: { size?: number }) {
  return (
    <span className="inline-flex shrink-0" style={{ width: size, height: size }}>
      <img src="/brand/varlatch-app-icon.png" width={size} height={size} alt="" className="brand-mark brand-on-dark" />
      <img
        src="/brand/varlatch-mark.png"
        width={size}
        height={size}
        alt=""
        className="brand-on-light object-contain p-[8%]"
      />
    </span>
  );
}
