# Brand and button guide

Use the official button so people recognise it. The assets are in
[`brand/`](../brand/) and served from `https://www.nobleid.org/brand/`.
Pick a button on [the Sign in with NobleID page](https://www.nobleid.org/sign-in-with-nobleid#buttons)
and copy its code, or let the browser SDK draw it: `NobleID.renderButton(...)`.

## The button files

Every button is in [`brand/buttons/`](../brand/buttons/), named

```
nobleid-<label>-<theme>-<shape>-<size>.svg
```

for example `nobleid-sign-in-black-pill-md.svg`. Every label exists in every
theme, shape and size: 135 files. The SDK's `label`, `theme`, `shape` and
`size` options take the same words.

| Part | Values |
|---|---|
| `label` | `sign-in` "Sign in with NobleID" · `continue` "Continue with NobleID" · `icon` the mark alone |
| `theme` | `white` · `black` · `green` · `outline-white` · `outline-black` |
| `shape` | `rounded` (8 px corners) · `pill` (fully rounded; a circle for `icon`) · `square` |
| `size` | `sm` 40 px · `md` 44 px · `lg` 48 px tall |

[`brand/buttons/manifest.json`](../brand/buttons/manifest.json) lists every
file with its width and height. The files are vector, with the label drawn
as outlines, so they need no font and stay sharp at any size. They are built
by `node scripts/build-buttons.mjs` from the mark in `brand/nobleid-mark.svg`;
do not edit them by hand.

The mark on its own:

| File | Use |
|---|---|
| `nobleid-mark.svg` | Green mark, for light backgrounds |
| `nobleid-mark-white.svg` | White mark, for dark or coloured backgrounds |

The original files (`sign-in-with-nobleid-light.svg`, `-dark.svg`,
`continue-with-nobleid-light.svg`, `-dark.svg` and the two
`sign-in-with-nobleid-icon-*` files) are still served, unchanged, so
existing pages keep working. For new pages, use `brand/buttons/`.

## Labels

Use exactly one of:

- **Sign in with NobleID**
- **Continue with NobleID**: where the same button signs people in and
  creates their account in your app.

Sign in with NobleID has no separate sign-up request (no `prompt=create`),
so there is no "Sign up with NobleID" button. Do not write "Login with Noble", "NobleID Login", or "Sign in with
NobleID account". Use the icon-only button only where every other sign-in
option is icon-only too.

## Themes

Pick the theme that stands out from the surface the button sits on: a
black button on a white page, a white or green one on a dark page.

| Theme | Background | Text | Border | Mark | Use on |
|---|---|---|---|---|---|
| `white` | `#FFFFFF` | `#101828` | `#D0D5DD` | green `#009966` | white, light or dark backgrounds (the grey border marks its edge on white) |
| `black` | `#101828` | `#FFFFFF` | `#101828` | white | white or light backgrounds |
| `green` | `#00734D` | `#FFFFFF` | `#00734D` | white | white, light or dark backgrounds |
| `outline-white` | none | `#FFFFFF` | `#FFFFFF` | white | dark or strongly coloured backgrounds, photos |
| `outline-black` | none | `#101828` | `#101828` | green `#009966` | light tinted backgrounds |

The green button is `#00734D`, a darker shade of the mark's green: white
text on the mark's own `#009966` is 3.6:1, too low for WCAG AA.

## Contrast

- Label text needs **4.5:1** against what is behind it (WCAG 2.2, 1.4.3).
  `white` (17.7:1), `black` (17.7:1) and `green` (5.9:1) bring their own
  background, so they pass anywhere.
- The outline themes have no background, so your surface decides:
  - `outline-white` needs a surface at least as dark as `#767676` grey.
  - `outline-black` needs a surface at least as light as `#808080` grey.
    For the icon-only button, the mark is all there is: use it only on
    surfaces at least as light as `#E9E9E9`, where the green mark reaches 3:1.
  - If you are not sure, use `white` or `black`.
- The mark is at least 3:1 against its own button in every solid theme.
- Check a colour pair with any WCAG contrast checker before you ship.

## Shape and size

- Use the same shape as the other sign-in buttons beside it: pill next to
  pills, square next to square buttons.
- Minimum height **40 px** (`sm`). Icon-only buttons are square, at least
  40 × 40 px. On touch screens, prefer `md` or `lg`.
- Scale a file only proportionally, and not below 40 px tall. Do not stretch,
  squash or crop it, and keep the mark and label on one line.
- Give it the same prominence as other sign-in options. Do not make it
  smaller than the buttons beside it.

## Clear space

Keep clear space around the button of at least half its height (20 px at
40 px tall). Nothing else goes inside that space: no text, icons or other
buttons.

## Focus and hover

The button is a real `<button>` or `<a>`, so it can be reached with the
keyboard.

- Keep the focus ring. The SDK keeps the browser's ring, 2 px clear of the
  button. Around an image button, do not set `outline: none`; if you style
  the ring yourself, make it at least 2 px thick, 2 px clear of the button,
  and 3:1 against the surface.
- A hover state is optional. The SDK darkens the background slightly.

```html
<a href="/auth/nobleid/start" class="nobleid-button">
  <img src="https://www.nobleid.org/brand/buttons/nobleid-sign-in-black-pill-md.svg"
       alt="Sign in with NobleID" width="218" height="44">
</a>
<style>
  .nobleid-button { display: inline-block; line-height: 0; border-radius: 22px; }
  .nobleid-button:focus-visible { outline: 2px solid #2E90FA; outline-offset: 2px; }
</style>
```

## Accessibility

- The accessible name is the label: `alt="Sign in with NobleID"` on the
  image, or `aria-label` on an icon-only button. The SDK sets it.
- The mark inside the SDK's button is decorative (`alt=""`).
- Every file also carries `role="img"`, `aria-label` and a `<title>` with
  its label, for when it is used inline.

## Do not

- Recolour, outline, rotate, animate, crop or redraw the mark. Use the green
  or the white mark as provided.
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

## Researcher badge

`NobleID.renderResearcherBadge(container, claims)` shows the person's name,
their NobleID (linked to their public profile) and only the verification
markers present and true in the claims you received. Show it only for the
person who signed in, or for people who agreed to show it. It is not a
certificate: link to the NobleID profile rather than copying the markers into
your own UI.
