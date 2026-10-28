# Brand and button guide

Use the official button so people recognise it. The assets are in
[`brand/`](../brand/) and served from `https://www.nobleid.org/brand/`.

| File | Use |
|---|---|
| `sign-in-with-nobleid-light.svg` | "Sign in with NobleID", light background |
| `sign-in-with-nobleid-dark.svg` | "Sign in with NobleID", dark background |
| `continue-with-nobleid-light.svg` | "Continue with NobleID", light background |
| `continue-with-nobleid-dark.svg` | "Continue with NobleID", dark background |
| `sign-in-with-nobleid-icon-light.svg` | Icon-only button, light (40 × 40) |
| `sign-in-with-nobleid-icon-dark.svg` | Icon-only button, dark (40 × 40) |
| `nobleid-mark.svg` | The NobleID mark on its own |

Or let the browser SDK draw the button: `NobleID.renderButton(...)`.

## Labels

Use exactly one of:

- **Sign in with NobleID**
- **Continue with NobleID**

Do not write "Login with Noble", "NobleID Login", or "Sign in with NobleID
account".

## Themes

| Theme | Background | Text | Border |
|---|---|---|---|
| Light | `#FFFFFF` | `#101828` | `#D0D5DD` |
| Dark | `#101828` | `#FFFFFF` | `#101828` |

The mark is green (`#009966`) on both themes. Pick the theme that contrasts
with the surface the button sits on.

## Size and spacing

- Minimum height **40 px**. The SDK's sizes are 40, 44 and 48 px.
- Corner radius 8 px.
- Keep clear space around the button of at least half its height
  (20 px at 40 px tall). Nothing else inside that space.
- Keep the mark and label on one line. Do not stretch or squash the SVGs;
  scale them proportionally.
- Give it the same prominence as other sign-in options. Do not make it
  smaller than the buttons beside it.

## Do not

- Recolour, outline, rotate, animate, crop or redraw the mark.
- Put the mark on a busy image or a colour that hides it.
- Combine the mark with your logo into a new logo.
- Use the mark or the name to suggest NobleID endorses, sponsors or verifies
  your app or your content. An app is "verified" only when NobleID shows the
  badge on its consent screen.
- Use the button for anything other than starting Sign in with NobleID.

## Trademarks and forks

"NobleID", "Sign in with NobleID" and the NobleID mark are NobleID's
trademarks. The Apache License covers this kit's code and text only; it
grants no right to use the name or the mark (section 6). You may use the
official button, unmodified, to start Sign in with NobleID, as described on
this page.

A fork or modified version of this kit must not use the NobleID name or mark
in its own name, package names, logo or listing, or present itself as
official. It may say that it is "compatible with Sign in with NobleID".
The only official sources are this repository and `www.nobleid.org`.

## Accessibility

The button is a real `<button>` or `<a>` with an accessible name equal to the
label. The mark is decorative (`alt=""`). Keep focus styles visible.

## Researcher badge

`NobleID.renderResearcherBadge(container, claims)` shows the person's name,
their NobleID (linked to their public profile) and only the verification
markers present and true in the claims you received. Show it only for the
person who signed in, or for people who agreed to show it. It is not a
certificate: link to the NobleID profile rather than copying the markers into
your own UI.
