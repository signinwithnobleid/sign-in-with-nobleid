/**
 * The button set: every label, theme, shape and size, and the geometry of
 * each. One table for the SVG files (scripts/build-buttons.mjs), the browser
 * SDK (sdk/nobleid-auth.js keeps an ES5 copy; test/brand.test.mjs checks the
 * two agree) and the brand guide (docs/brand.md).
 */

/** File-name token → accessible name. `icon` is the mark alone. */
export const LABELS = {
  "sign-in": "Sign in with NobleID",
  continue: "Continue with NobleID",
  icon: "Sign in with NobleID",
};

export const MARK = { green: "#009966", white: "#FFFFFF" };

/**
 * `bg: null` is transparent: the outline themes sit on a coloured surface.
 * Green is the design system's primary green (#00734D), not the mark's
 * #009966: white text on #009966 is 3.6:1, below WCAG AA; on #00734D it is 5.9:1.
 */
export const THEMES = {
  white: { bg: "#FFFFFF", border: "#D0D5DD", text: "#101828", mark: "green", hover: "#F9FAFB", use: "white, light or dark backgrounds" },
  black: { bg: "#101828", border: "#101828", text: "#FFFFFF", mark: "white", hover: "#1D2939", use: "white or light backgrounds" },
  green: { bg: "#00734D", border: "#00734D", text: "#FFFFFF", mark: "white", hover: "#004D33", use: "white, light or dark backgrounds" },
  "outline-white": { bg: null, border: "#FFFFFF", text: "#FFFFFF", mark: "white", hover: "rgba(255,255,255,0.12)", use: "dark or strongly coloured backgrounds and photos" },
  "outline-black": { bg: null, border: "#101828", text: "#101828", mark: "green", hover: "rgba(16,24,40,0.06)", use: "light coloured backgrounds" },
};

/** Corner radius in px; `pill` is half the height (a circle for the icon button). */
export const SHAPES = { rounded: 8, pill: "full", square: 0 };

/**
 * h: height; mark: the mark's width (it is 1112 × 1080, so a little shorter);
 * font: label size; pad: left padding (right is pad + 4); gap: mark to label.
 * Pill buttons add 4 px on each side so the mark clears the curve.
 */
export const SIZES = {
  sm: { h: 40, mark: 20, font: 14, pad: 12, gap: 10 },
  md: { h: 44, mark: 22, font: 15, pad: 14, gap: 10 },
  lg: { h: 48, mark: 24, font: 16, pad: 16, gap: 12 },
};

export const PILL_EXTRA = 4;

/** brand/buttons/<this>. Predictable: nobleid-<label>-<theme>-<shape>-<size>.svg */
export function buttonFile(label, theme, shape, size) {
  return `nobleid-${label}-${theme}-${shape}-${size}.svg`;
}

export function* everyButton() {
  for (const label of Object.keys(LABELS))
    for (const theme of Object.keys(THEMES))
      for (const shape of Object.keys(SHAPES))
        for (const size of Object.keys(SIZES)) yield { label, theme, shape, size, file: buttonFile(label, theme, shape, size) };
}

/** Horizontal padding [left, right] for a full button. */
export function padding(shape, size) {
  const s = SIZES[size];
  const extra = shape === "pill" ? PILL_EXTRA : 0;
  return [s.pad + extra, s.pad + 4 + extra];
}

export function radius(shape, h) {
  const r = SHAPES[shape];
  return r === "full" ? h / 2 : r;
}

/* WCAG 2.2 relative luminance and contrast. */
function lum(hex) {
  const v = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
}
export function contrast(a, b) {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
