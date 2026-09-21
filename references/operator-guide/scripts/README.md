# Generating Audio from Video Scripts

These scripts are designed to be narrated using **Kokoro** (`hexgrad/kokoro`), a local, offline TTS engine. Kokoro is managed by Hermes and requires no PortShim code changes.

## Quick Start

```bash
# Install (Hermes manages this, one-time)
pip install kokoro soundfile

# Generate audio from any script
python scripts/narrate.py references/operator-guide/scripts/01-quick-start-script.md
```

## Voice Settings

| Setting | Value | Notes |
|---|---|---|
| Language | `b` | British English — closest to Australian |
| Voice | `bf_emma` | Female British voice |
| Speed | `1.0` | Default, can adjust for pacing |
| Sample rate | 24000 Hz | Kokoro native |

Available British voices: `bf_emma`, `bf_isabella`, `bf_alice`, `bm_george`, `bm_lewis`, `bm_daniel`.

## Manual Generation (Without the Narrate Script)

```python
from kokoro import KPipeline
import soundfile as sf

pipeline = KPipeline(lang_code='b')
text = "Your narration text here."
generator = pipeline(text, voice='bf_emma', speed=1.0)
for i, (_, _, audio) in enumerate(generator):
    sf.write(f'scene_{i:02d}.wav', audio, 24000)
```

## Video Assembly

After generating scene WAV files:

```bash
# 1. Export slides as PNG images from the PowerPoint/Keynote deck
# 2. Stitch each slide with its narration:
ffmpeg -loop 1 -i slide_01.png -i scene_00.wav \
  -c:v libx264 -tune stillimage -c:a aac -b:a 192k \
  -pix_fmt yuv420p -shortest scene_01.mp4

# 3. Concatenate all scenes:
ffmpeg -f concat -safe 0 -i scenes.txt -c copy final.mp4
```

Where `scenes.txt` contains:
```
file 'scene_01.mp4'
file 'scene_02.mp4'
...
```

## Notes

- Kokoro runs entirely offline — no API keys, no internet after model download
- The 82M parameter model downloads automatically on first use (~300MB)
- CPU inference is real-time — narration generates faster than playback
- No espeak-ng required for English on Windows (Kokoro falls back to its own phonemiser)
