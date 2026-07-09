---
name: video-production
description: Produce narrated tutorial videos from PortShim markdown scripts — TTS narration via Kokoro, slide generation, background music sourcing, and ffmpeg assembly. Use when creating video content for operator guides or documentation.
version: 1.0.0
author: PortShim
license: MIT
---

# Video Production from Documentation

End-to-end pipeline for producing narrated tutorial videos from PortShim operator guide scripts.

## Pipeline Overview

```
Script (.md) ──→ Narration audio (.wav) ──┐
                                           │
Script (.md) ──→ Slides (.png) ────────────┼──→ ffmpeg ──→ Scene (.mp4)
                                           │
                    Background music ──────┘
                                                    │
                              ┌─────────────────────┘
                              ▼
                    concat scenes ──→ Final (.mp4)
```

## Quick Start

```bash
# 1. Generate narration from a script
python scripts/narrate.py references/operator-guide/scripts/01-quick-start-script.md

# 2. Create slides from the script (manual — use PowerPoint/Keynote)
#    Export as PNG: scene_01.png, scene_02.png, ...

# 3. Source background music (see Music section below)

# 4. Assemble
bash scripts/assemble-video.sh output/01-quick-start/
```

---

## Step 1: Narration (Kokoro TTS)

Kokoro is a local, offline TTS engine (82M params, CPU real-time). Hermes manages the Kokoro installation — PortShim only references it in documentation.

### Generate per-scene audio

```bash
python scripts/narrate.py references/operator-guide/scripts/01-quick-start-script.md --out output/01-quick-start/
```

Output: `scene_01.wav`, `scene_02.wav`, ... — one file per script scene.

### Voice Settings

| Parameter | Value | Notes |
|---|---|---|
| Language | `b` | British English — closest to Australian |
| Voice | `bf_emma` | Female British — clear, professional |
| Speed | `1.0` | Adjust if pacing feels off (0.9 slower, 1.1 faster) |
| Format | 24kHz 16-bit WAV | Kokoro native, ffmpeg compatible |

### Manual Kokoro invocation

```python
from kokoro import KPipeline
import soundfile as sf

pipeline = KPipeline(lang_code='b')
text = open('scene_text.txt').read()
generator = pipeline(text, voice='bf_emma', speed=1.0)
for i, (_, _, audio) in enumerate(generator):
    sf.write(f'scene_{i:02d}.wav', audio, 24000)
```

---

## Step 2: Slides

Slides are created manually from the script's scene descriptions. Each scene marker in the script (`## SCENE N — TITLE (DURATION)`) maps to one slide.

### Slide Design Guidelines

- **Colours:** `#CC4141` (accent red), `#333333` (dark), `#F5F5F5` (light bg)
- **Font:** Calibri
- **Layout:** Title at top, 1-3 bullet points or a single visual, code in dark terminal-style blocks
- **Resolution:** 1920×1080 (YouTube standard)
- **Export:** One PNG per slide, named `scene_01.png`, `scene_02.png`, ...

### Scene-to-Slide Mapping

Each script scene has:
- **Duration** (in the scene header)
- **Visual directions** (bold text in the script)
- **Narration text** (body text — this is what gets spoken)

The slide should show the **Visual** direction content while the **Narration** plays.

---

## Step 3: Background Music

### Free Sources (No Attribution Required)

| Source | URL | Notes |
|---|---|---|
| **YouTube Audio Library** | youtube.com/audiolibrary | Free for YouTube videos, huge selection |
| **Pixabay Music** | pixabay.com/music | Free, no attribution, requires account |
| **StreamBeats** | streambeats.com | Completely free, no attribution, stream-safe |
| **Uppbeat** | uppbeat.io | Free with attribution, premium without |

### Free Sources (Attribution Required)

| Source | Attribution Format |
|---|---|
| **Incompetech** (Kevin MacLeod) | "Music: [Title] by Kevin MacLeod (incompetech.com)" |
| **Bensound** | "Music: bensound.com" |
| **Free Music Archive** | Varies by track — check license |

### Music Selection Criteria

For tutorial/instructional videos:
- **Instrumental only** — no vocals competing with narration
- **Tempo:** 90-110 BPM — energetic but not distracting
- **Genre:** Corporate, ambient, lo-fi, light electronic
- **Volume:** -18dB to -22dB below narration (background, not foreground)
- **Duration:** At least as long as the final video (can loop)

### Download and Prepare

```bash
# 1. Download track (example: Pixabay)
# 2. Trim or loop to match video duration
ffmpeg -stream_loop -1 -i background.mp3 -t DURATION -c copy bg_looped.mp3

# 3. Lower volume to background level
ffmpeg -i bg_looped.mp3 -filter:a "volume=-20dB" bg_quiet.mp3
```

---

## Step 4: Assembly

### Per-Scene Assembly

For each scene, combine slide image + narration audio:

```bash
for i in $(seq -w 1 N); do
    ffmpeg -loop 1 -i "scene_${i}.png" \
           -i "scene_${i}.wav" \
           -c:v libx264 -tune stillimage \
           -c:a aac -b:a 192k \
           -pix_fmt yuv420p \
           -shortest \
           "scene_${i}.mp4"
done
```

### Mix in Background Music

```bash
for i in $(seq -w 1 N); do
    ffmpeg -i "scene_${i}.mp4" -i bg_quiet.mp3 \
           -filter_complex "[1:a]atrim=0:$(ffprobe -v error -show_entries format=duration -of csv=p=0 scene_${i}.wav)[bg];[0:a][bg]amix=inputs=2:duration=first:weights=1 0.15" \
           -c:v copy -c:a aac -b:a 192k \
           "scene_${i}_mixed.mp4"
done
```

### Concatenate All Scenes

Create `scenes.txt`:
```
file 'scene_01_mixed.mp4'
file 'scene_02_mixed.mp4'
file 'scene_03_mixed.mp4'
...
```

```bash
ffmpeg -f concat -safe 0 -i scenes.txt -c copy final.mp4
```

### Add Title Card and Outro

Every video has a standardised intro and outro built into the script:
- **Scene 1 (0:10):** PortShim title card with guide name, brief musical sting
- **Final Scene (0:15):** End card with GitHub URL, music fade-out

The intro and outro are rendered as regular scenes — no special ffmpeg handling needed.
They're included in `scenes.txt` like any other scene.

---

## Script-to-Video Mapping

| Operator Guide | Script File | Est. Duration | Scenes |
|---|---|---|---|
| Quick Start | `01-quick-start-script.md` | ~7 min | 14 |
| Phase Decision Guide | `02-phase-decision-guide-script.md` | ~12 min | 10 |
| Pre-Engagement Checklist | `03-pre-engagement-checklist-script.md` | ~8 min | 11 |

---

## Deliverables

| File | Description |
|---|---|
| `final.mp4` | Finished video, H.264/AAC, 1920×1080 |
| `scenes/` | Individual scene MP4s (can reorder or replace scenes) |
| `audio/` | Raw narration WAVs (can regenerate with different voice/speed) |
| `slides/` | Slide PNGs (source for re-render) |

---

## Pitfalls

| Pitfall | Fix |
|---|---|
| Narration pacing feels off | Adjust Kokoro `speed` parameter (0.9 = slower, 1.1 = faster) |
| Slide duration doesn't match narration | Use `ffprobe` to get exact audio duration, set slide to match |
| Background music too loud | Mix at `weights=1 0.1` to `0.2` — narration should dominate |
| Black frames between scenes | Ensure all scene MP4s have identical codec settings (use same ffmpeg command) |
| File size too large | Add `-crf 23` to H.264 encode (lower = better quality, larger file) |
| Kokoro model download stalls | Model is ~300MB. First run downloads automatically. Be patient. |
| British voice sounds too formal | Try `bf_isabella` (warmer) or `bm_lewis` (male, authoritative) |

## Uploading to YouTube

```bash
# If you have youtube-upload installed:
youtube-upload --title="PortShim: Operator's Quick Start" \
  --description="Step-by-step guide to running your first security assessment with PortShim." \
  --category="Science & Technology" \
  --privacy="unlisted" \
  final.mp4
```

Otherwise, upload manually via youtube.com/upload.
