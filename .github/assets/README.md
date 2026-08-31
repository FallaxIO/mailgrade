# Brand assets

| File | Use |
| --- | --- |
| `banner-light.svg` / `banner-dark.svg` | README header, 1200×340, picked by `prefers-color-scheme` |
| `logo.svg` | 64×64 tile, safe down to 16px |
| `logomark.svg` | the bare mark, `stroke: currentColor` |
| `social-preview.png` | 1280×640, upload under Settings → Social preview |

## The mark

An envelope whose body tapers into a shield: the two things the library is
about, in one shape. It is drawn on a 64 grid entirely at 45°, in one stroke
weight, with mitred joins and no curves. The crease apex sits exactly on the
shoulder where the sides meet the point.

## Colours

Monochrome, with colour reserved for the three verdicts.

| Token | Dark | Light |
| --- | --- | --- |
| background | `#000000` | `#FFFFFF` |
| foreground | `#FFFFFF` | `#000000` |
| secondary / dim | `#A1A1A1` / `#6F6F6F` | `#666666` / `#8F8F8F` |
| hairline | `#1F1F1F` | `#EAEAEA` |
| `protected` | `#00D8A3` | `#008F73` |
| `partial` | `#F5A623` | `#B76E00` |
| `spoofable` | `#FF5C63` | `#D93036` |

## Type

[Geist](https://vercel.com/font) for the wordmark and prose, Geist Mono for
records and verdicts, both OFL. All text is converted to outlines, so the SVGs
render identically everywhere and load no fonts. Editing the copy means
regenerating the file, not editing its paths.
