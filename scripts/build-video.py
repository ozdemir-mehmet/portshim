#!/usr/bin/env python3
"""
build-video.py — Parse a PortShim video script and generate:
  - Per-scene narration audio (WAV via Kokoro)
  - Per-scene slide images (PNG, 1920×1080, SSW styling)

Usage:
    python scripts/build-video.py references/operator-guide/scripts/01-quick-start-script.md --out output/01-quick-start/
"""

import os
import re
import sys
import argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

# ── SSW Brand Colours ──
RED = (204, 65, 65)
DARK = (51, 51, 51)
MED = (121, 121, 121)
LIGHT = (245, 245, 245)
WHITE = (255, 255, 255)
BG_DARK = (30, 30, 30)
CODE_BG = (40, 40, 40)

WIDTH, HEIGHT = 1920, 1080

# ── Script Parser ─────────────────────────────────────────────────────

def _clean_narration(text):
    """Remove code blocks and URLs from narration text — these appear on slides, not spoken."""
    # Remove fenced code blocks
    text = re.sub(r'```.*?```', '', text, flags=re.DOTALL)
    # Remove lines that are clearly shell commands or URLs
    lines = []
    for line in text.split('\n'):
        stripped = line.strip()
        # Skip: URLs, shell commands, code patterns
        if re.match(r'^(https?://|git\s|python\s|pip\s|nuclei\s|nmap\s|curl\s|/\w+|\$|#>|mkdir\s|cd\s)', stripped):
            continue
        # Skip lines that are just paths or CLI flags
        if re.match(r'^(--?\w+|[\w/]+\.[\w]{2,4}\s)', stripped):
            continue
        lines.append(line)
    return '\n'.join(lines)


def parse_script(script_path):
    """Parse a PortShim video script into scenes with narration text."""
    with open(script_path, 'r', encoding='utf-8') as f:
        content = f.read()

    # Extract guide title from first heading
    title_match = re.search(r'^# Video Script: (.+)$', content, re.MULTILINE)
    guide_title = title_match.group(1).strip() if title_match else script_path.stem

    scenes = []
    current_scene = None
    current_body = []

    for line in content.split('\n'):
        scene_match = re.match(r'^## SCENE\s+(\d+|OUTRO)\s*[—\-]\s*(.+?)\s*\((\d+:\d+)\)', line)
        if scene_match:
            if current_scene:
                raw = '\n'.join(current_body).strip()
                current_scene['narration'] = _clean_narration(raw)
                current_scene['raw'] = raw
                scenes.append(current_scene)
            current_scene = {
                'id': scene_match.group(1),
                'title': scene_match.group(2).strip(),
                'duration': scene_match.group(3),
                'visual': '',
                'narration': '',
            }
            current_body = []
            continue

        if current_scene is None:
            continue

        if line.startswith('## PRODUCTION NOTES'):
            if current_scene:
                raw = '\n'.join(current_body).strip()
                current_scene['narration'] = _clean_narration(raw)
                current_scene['raw'] = raw
                scenes.append(current_scene)
            current_scene = None
            break

        if line.strip() == '---':
            continue

        if line.startswith('**Visual:'):
            current_scene['visual'] = line.replace('**Visual:**', '').strip()
            continue

        if line.startswith('**Audio:'):
            continue

        stripped = line.strip()
        if stripped and not stripped.startswith('#') and not stripped.startswith('**'):
            current_body.append(stripped)
        elif stripped == '' and current_body and current_body[-1] != '':
            current_body.append('')

    if current_scene:
        raw = '\n'.join(current_body).strip()
        current_scene['narration'] = _clean_narration(raw)
        current_scene['raw'] = raw
        scenes.append(current_scene)

    return guide_title, scenes


# ── Narration Generator (Kokoro) ───────────────────────────────────────

def generate_slides_for_video(scenes, output_dir):
    """Generate slides using the rich slide renderer from build-slides.py."""
    import sys
    from pathlib import Path
    scripts_dir = str(Path(__file__).resolve().parent)
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    from build_slides import generate_slides as _gen
    _gen(scenes, output_dir)


def generate_narration(scenes, output_dir, voice='bf_isabella', speed=1.0):
    """Generate WAV narration for each scene using Kokoro."""
    from kokoro import KPipeline
    import soundfile as sf

    pipeline = KPipeline(lang_code='b')
    audio_dir = Path(output_dir) / 'audio'
    audio_dir.mkdir(parents=True, exist_ok=True)

    for scene in scenes:
        text = scene['narration']
        if not text:
            print(f'  Scene {scene["id"]}: SKIP (no narration)')
            continue

        scene_id = str(scene['id']).zfill(2) if scene['id'] != 'OUTRO' else 'outro'
        wav_path = audio_dir / f'scene_{scene_id}.wav'

        if wav_path.exists():
            print(f'  Scene {scene_id}: EXISTS ({wav_path.stat().st_size} bytes)')
            continue

        print(f'  Scene {scene_id}: generating... ', end='', flush=True)
        try:
            import numpy as np
            generator = pipeline(text, voice=voice, speed=speed)
            all_audio = []
            for _, _, audio in generator:
                all_audio.append(audio)
            if all_audio:
                combined = np.concatenate(all_audio) if len(all_audio) > 1 else all_audio[0]
                sf.write(str(wav_path), combined, 24000)
            print(f'OK ({wav_path.stat().st_size} bytes, {len(combined)/24000:.1f}s)')
        except Exception as e:
            print(f'ERROR: {e}')


# ── Slide Generator ───────────────────────────────────────────────────

def _get_font(size, bold=False):
    """Get Calibri font, falling back to Arial, then default."""
    for name in ['calibri.ttf', 'Calibri.ttf', 'calibrib.ttf', 'arial.ttf', 'Arial.ttf']:
        try:
            return ImageFont.truetype(name, size)
        except (IOError, OSError):
            pass
    return ImageFont.load_default()


def _draw_text_box(draw, text, x, y, max_width, font, colour, line_spacing=6):
    """Draw wrapped text, returning the bottom y position."""
    words = text.split()
    lines = []
    current_line = []
    for word in words:
        test_line = ' '.join(current_line + [word])
        bbox = draw.textbbox((0, 0), test_line, font=font)
        if bbox[2] - bbox[0] <= max_width:
            current_line.append(word)
        else:
            if current_line:
                lines.append(' '.join(current_line))
            current_line = [word]
    if current_line:
        lines.append(' '.join(current_line))

    cy = y
    for line in lines:
        draw.text((x, cy), line, fill=colour, font=font)
        cy += font.size + line_spacing
    return cy


def _add_red_bar(draw, y, height=4):
    """Draw a red accent bar at the given y position."""
    draw.rectangle([60, y, 300, y + height], fill=RED)


def _add_code_block(draw, text, x, y, max_width, font):
    """Draw text on a dark code-style background."""
    lines = text.split('\n')
    line_height = font.size + 4
    # Background
    draw.rectangle(
        [x - 20, y - 15, x + max_width + 20, y + len(lines) * line_height + 10],
        fill=CODE_BG
    )
    cy = y
    for line in lines:
        draw.text((x, cy), line, fill=WHITE, font=font)
        cy += line_height


def generate_slides(scenes, output_dir):
    """Generate 1920×1080 PNG slides for each scene."""
    slide_dir = Path(output_dir) / 'slides'
    slide_dir.mkdir(parents=True, exist_ok=True)

    big_font = _get_font(52, bold=True)
    med_font = _get_font(36, bold=False)
    small_font = _get_font(28, bold=False)
    code_font = _get_font(24, bold=False)
    title_font = _get_font(72, bold=True)

    for scene in scenes:
        scene_id = str(scene['id']).zfill(2) if scene['id'] != 'OUTRO' else 'outro'
        png_path = slide_dir / f'scene_{scene_id}.png'

        if png_path.exists():
            print(f'  Scene {scene_id}: EXISTS')
            continue

        # Handle special scenes
        if scene['id'] == '1':
            # Intro title card
            img = Image.new('RGB', (WIDTH, HEIGHT), BG_DARK)
            draw = ImageDraw.Draw(img)

            # Red accent bar
            draw.rectangle([0, HEIGHT // 2 - 200, WIDTH, HEIGHT // 2 - 196], fill=RED)

            # Title
            bbox = draw.textbbox((0, 0), 'PORTSHIM', font=title_font)
            tw = bbox[2] - bbox[0]
            draw.text(((WIDTH - tw) // 2, HEIGHT // 2 - 160), 'PORTSHIM', fill=WHITE, font=title_font)

            # Subtitle
            subtitle = scene.get('title', '')
            if subtitle:
                subtitle_font = _get_font(32, bold=False)
                bbox = draw.textbbox((0, 0), subtitle, font=subtitle_font)
                sw = bbox[2] - bbox[0]
                draw.text(((WIDTH - sw) // 2, HEIGHT // 2 - 70), subtitle, fill=MED, font=subtitle_font)

            # Tagline
            tag_font = _get_font(24, bold=False)
            tagline = 'On-Site Security Assessment Pipeline'
            bbox = draw.textbbox((0, 0), tagline, font=tag_font)
            tw2 = bbox[2] - bbox[0]
            draw.text(((WIDTH - tw2) // 2, HEIGHT // 2), tagline, fill=RED, font=tag_font)

        elif scene['id'] == 'OUTRO':
            # Outro end card
            img = Image.new('RGB', (WIDTH, HEIGHT), BG_DARK)
            draw = ImageDraw.Draw(img)

            # Top red bar
            draw.rectangle([0, 0, WIDTH, 6], fill=RED)

            # Title
            bbox = draw.textbbox((0, 0), 'PORTSHIM', font=title_font)
            tw = bbox[2] - bbox[0]
            draw.text(((WIDTH - tw) // 2, HEIGHT // 2 - 120), 'PORTSHIM', fill=WHITE, font=title_font)

            # GitHub URL
            url_font = _get_font(36, bold=False)
            url = 'github.com/ozdemir-mehmet/portshim'
            bbox = draw.textbbox((0, 0), url, font=url_font)
            uw = bbox[2] - bbox[0]
            draw.text(((WIDTH - uw) // 2, HEIGHT // 2 + 20), url, fill=RED, font=url_font)

            # Licence
            lic_font = _get_font(24, bold=False)
            lic = 'Open Source — MIT Licence'
            bbox = draw.textbbox((0, 0), lic, font=lic_font)
            lw = bbox[2] - bbox[0]
            draw.text(((WIDTH - lw) // 2, HEIGHT // 2 + 90), lic, fill=MED, font=lic_font)

        else:
            # Standard content slide
            img = Image.new('RGB', (WIDTH, HEIGHT), BG_DARK)
            draw = ImageDraw.Draw(img)

            # Red accent bar at top
            draw.rectangle([0, 0, WIDTH, 6], fill=RED)

            # Scene title
            title = scene.get('title', '')
            draw.text((80, 50), title, fill=WHITE, font=big_font)

            # Body text — use narration preview (first 300 chars)
            body = scene.get('narration', '')
            if not body and scene.get('visual'):
                body = scene['visual']
            body = body[:350]

            y = 160
            if body:
                y = _draw_text_box(draw, body, 80, y, WIDTH - 160, med_font, LIGHT, line_spacing=10)

            # If visual direction is different from narration, show it
            visual = scene.get('visual', '')
            if visual and visual != body:
                y += 20
                _add_red_bar(draw, y, 3)
                y += 15
                _draw_text_box(draw, visual, 80, y, WIDTH - 160, small_font, RED, line_spacing=6)

        print(f'  Scene {scene_id}: rendered')
        img.save(str(png_path))


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Build video assets from a PortShim script')
    parser.add_argument('script', help='Path to video script .md file')
    parser.add_argument('--out', '-o', default=None, help='Output directory')
    parser.add_argument('--audio-only', action='store_true', help='Only generate narration')
    parser.add_argument('--slides-only', action='store_true', help='Only generate slides')
    parser.add_argument('--voice', default='bf_emma', help='Kokoro voice (default: bf_emma)')
    parser.add_argument('--speed', type=float, default=1.0, help='Speech speed (default: 1.0)')
    args = parser.parse_args()

    script_path = Path(args.script)
    if not script_path.exists():
        print(f'ERROR: Script not found: {script_path}')
        sys.exit(1)

    output_dir = args.out or f'output/{script_path.stem.replace("-script","")}'

    print(f'Parsing script: {script_path.name}')
    guide_title, scenes = parse_script(script_path)
    print(f'Guide: {guide_title}')
    print(f'Scenes: {len(scenes)}')
    print()

    if not args.slides_only:
        print('Generating narration...')
        generate_narration(scenes, output_dir, voice=args.voice, speed=args.speed)
        print()

    if not args.audio_only:
        print('Generating slides...')
        generate_slides_for_video(scenes, output_dir)
        print()

    print(f'Done. Output: {output_dir}/')


if __name__ == '__main__':
    main()
