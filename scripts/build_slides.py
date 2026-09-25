#!/usr/bin/env python3
"""
build-slides.py — Generate rich, visual 1920×1080 slides from parsed script scenes.
Handles: title cards, code blocks, bullet lists, flow diagrams, decision matrices.

Not meant to be called directly — imported by build-video.py.
"""
from PIL import Image, ImageDraw, ImageFont
import re

WIDTH, HEIGHT = 1920, 1080

# ── Brand Colours ──
RED = (204, 65, 65)
DARK = (51, 51, 51)
MED = (121, 121, 121)
LIGHT = (200, 200, 200)
WHITE = (255, 255, 255)
BG = (24, 24, 28)  # Dark background
CODE_BG = (35, 35, 42)
CARD_BG = (40, 40, 48)
GREEN = (80, 200, 120)
YELLOW = (220, 180, 60)
BLUE = (80, 150, 220)

# ── Fonts ──
def _font(size, bold=False):
    for name in ['calibrib.ttf', 'calibri.ttf', 'arialbd.ttf', 'arial.ttf'] if bold else ['calibri.ttf', 'arial.ttf']:
        try:
            return ImageFont.truetype(name, size)
        except (IOError, OSError):
            pass
    return ImageFont.load_default()

TITLE_F = _font(56, True)
BIG_F = _font(44, True)
MED_F = _font(32)
BODY_F = _font(28)
SMALL_F = _font(24)
CODE_F = _font(22)
HUGE_F = _font(80, True)

# ── Drawing Helpers ──

def _text_box(draw, text, x, y, w, font, colour, spacing=8):
    """Draw word-wrapped text. Returns bottom y + spacing."""
    words = text.split()
    lines, cur = [], []
    for word in words:
        test = ' '.join(cur + [word])
        if draw.textbbox((0, 0), test, font=font)[2] <= w:
            cur.append(word)
        else:
            if cur: lines.append(' '.join(cur))
            cur = [word]
    if cur: lines.append(' '.join(cur))
    for line in lines:
        draw.text((x, y), line, fill=colour, font=font)
        y += font.size + spacing
    return y


def _red_bar(draw, y, w=240, h=5, x=80):
    draw.rectangle([x, y, x + w, y + h], fill=RED)


def _card(draw, x, y, w, h, colour=CARD_BG, radius=12):
    """Draw a rounded-rect card."""
    draw.rounded_rectangle([x, y, x + w, y + h], radius=radius, fill=colour)
    return x + 20, y + 20  # Return content start position


def _code_block(draw, code, x, y, max_w):
    """Draw a code block with dark background."""
    lines = code.strip().split('\n')
    line_h = CODE_F.size + 6
    total_h = len(lines) * line_h + 30
    draw.rounded_rectangle([x - 10, y - 5, x + max_w + 10, y + total_h], radius=8, fill=CODE_BG)
    cy = y + 10
    for line in lines:
        # Simple syntax colouring: grey for comments, green for strings, cyan for commands
        stripped = line.strip()
        if stripped.startswith('#') or stripped.startswith('//'):
            colour = MED
        elif stripped.startswith('"') or stripped.startswith("'"):
            colour = YELLOW
        elif any(stripped.startswith(kw) for kw in ['git', 'python', 'pip', 'nuclei', 'npm', 'curl', 'cd', 'mkdir']):
            colour = GREEN
        else:
            colour = LIGHT
        draw.text((x, cy), line, fill=colour, font=CODE_F)
        cy += line_h
    return y + total_h + 10


def _pipeline_flow(draw, center_x, y):
    """Draw the 6-phase pipeline flow diagram."""
    phases = [
        ('Phase 0\nSetup', RED),
        ('Phase 1\nRecon', BLUE),
        ('Phase 2\nVuln', BLUE),
        ('Phase 3\nExploit', YELLOW),
        ('Phase 4\nReport', GREEN),
        ('Phase 5\nRetest', GREEN),
    ]
    box_w, box_h = 140, 80
    gap = 30
    total_w = len(phases) * box_w + (len(phases) - 1) * gap
    start_x = center_x - total_w // 2

    for i, (label, colour) in enumerate(phases):
        bx = start_x + i * (box_w + gap)
        # Box
        draw.rounded_rectangle([bx, y, bx + box_w, y + box_h], radius=10, fill=colour)
        # Label
        for j, line in enumerate(label.split('\n')):
            bbox = draw.textbbox((0, 0), line, font=SMALL_F)
            tw = bbox[2] - bbox[0]
            draw.text((bx + (box_w - tw) // 2, y + 10 + j * 28), line, fill=WHITE, font=SMALL_F)

        # Gate label between phases
        if i < len(phases) - 1:
            gx = bx + box_w
            gate_text = f'Gate {i}'
            bbox = draw.textbbox((0, 0), gate_text, font=CODE_F)
            gw = bbox[2] - bbox[0]
            # Arrow
            draw.rectangle([gx + 4, y + box_h // 2, gx + gap - 4, y + box_h // 2 + 2], fill=MED)
            draw.text((gx + (gap - gw) // 2, y + box_h + 5), gate_text, fill=MED, font=CODE_F)

    return y + box_h + 50


def _decision_matrix(draw, x, y, w):
    """Draw the 4-option decision matrix."""
    options = [
        ('APPROVE', GREEN, 'Output correct. Proceed.'),
        ('RERUN', BLUE, "Repeat with different parameters."),
        ('MODIFY SCOPE', YELLOW, 'Adjust target range or settings.'),
        ('ABORT', RED, 'Stop immediately. Save output.'),
    ]
    card_w = (w - 60) // 4
    for i, (label, colour, desc) in enumerate(options):
        cx = x + i * (card_w + 20)
        # Card
        draw.rounded_rectangle([cx, y, cx + card_w, y + 140], radius=10, fill=CARD_BG)
        # Colour bar at top
        draw.rectangle([cx, y, cx + card_w, y + 6], fill=colour)
        # Label
        bbox = draw.textbbox((0, 0), label, font=BODY_F)
        lw = bbox[2] - bbox[0]
        draw.text((cx + (card_w - lw) // 2, y + 20), label, fill=colour, font=BODY_F)
        # Description
        _text_box(draw, desc, cx + 15, y + 60, card_w - 30, SMALL_F, LIGHT, spacing=4)

    return y + 150


def _checklist(draw, items, x, y, w):
    """Draw a checklist with bullet points."""
    cy = y
    for item in items:
        # Bullet using ASCII dash for universal font support
        draw.text((x, cy), '—', fill=RED, font=BODY_F)
        cy = _text_box(draw, item, x + 30, cy, w - 30, BODY_F, LIGHT, spacing=8)
        cy += 12
    return cy


# ── Scene Renderers ──

def render_intro(scene, out_path):
    """Title card intro scene."""
    img = Image.new('RGB', (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)

    # Red accent
    draw.rectangle([0, HEIGHT // 2 - 180, WIDTH, HEIGHT // 2 - 172], fill=RED)

    # Title
    title = 'PORTSHIM'
    bbox = draw.textbbox((0, 0), title, font=HUGE_F)
    tw = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw) // 2, HEIGHT // 2 - 150), title, fill=WHITE, font=HUGE_F)

    # Subtitle
    sub = scene.get('title', 'Operator\'s Quick Start')
    bbox = draw.textbbox((0, 0), sub, font=BIG_F)
    sw = bbox[2] - bbox[0]
    draw.text(((WIDTH - sw) // 2, HEIGHT // 2 - 70), sub, fill=RED, font=BIG_F)

    # Tagline
    tag = 'On-Site Security Assessment Pipeline'
    bbox = draw.textbbox((0, 0), tag, font=MED_F)
    tw2 = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw2) // 2, HEIGHT // 2 + 20), tag, fill=MED, font=MED_F)

    img.save(out_path)


def render_outro(scene, out_path):
    """End card outro scene."""
    img = Image.new('RGB', (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, WIDTH, 6], fill=RED)

    title = 'PORTSHIM'
    bbox = draw.textbbox((0, 0), title, font=HUGE_F)
    tw = bbox[2] - bbox[0]
    draw.text(((WIDTH - tw) // 2, HEIGHT // 2 - 120), title, fill=WHITE, font=HUGE_F)

    url = 'github.com/ozdemir-mehmet/portshim'
    bbox = draw.textbbox((0, 0), url, font=BIG_F)
    uw = bbox[2] - bbox[0]
    draw.text(((WIDTH - uw) // 2, HEIGHT // 2 + 20), url, fill=RED, font=BIG_F)

    lic = 'Open Source — MIT Licence'
    bbox = draw.textbbox((0, 0), lic, font=MED_F)
    lw = bbox[2] - bbox[0]
    draw.text(((WIDTH - lw) // 2, HEIGHT // 2 + 90), lic, fill=MED, font=MED_F)

    img.save(out_path)


def render_content_slide(scene, out_path):
    """Render a content slide based on the scene's visual direction and narration."""
    img = Image.new('RGB', (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, WIDTH, 6], fill=RED)

    title = scene.get('title', '')
    narration = scene.get('narration', '')
    visual = scene.get('visual', '')

    # Title at top
    draw.text((80, 30), title, fill=WHITE, font=BIG_F)
    _red_bar(draw, 85, 160, 3)

    content_y = 120
    content_x = 80
    content_w = WIDTH - 160
    
    # Raw text for content extraction (preserved before TTS cleaning)
    raw_text = scene.get('raw', narration)
    lines = [l.strip() for l in raw_text.split('\n') if l.strip()]

    # ── Detect content type and render accordingly ──
    # ── Detect content type from VISUAL hints (not narration — code is stripped for TTS) ──
    visual_lower = visual.lower()
    
    # Terminal / code
    has_code = any(kw in visual_lower for kw in ['terminal', 'code', 'command', 'git', 'python', 'pip', 'nuclei', 'nmap', '/skill', 'console'])
    # Checklist / bullets
    is_list = any(kw in visual_lower for kw in ['checklist', 'bullet', 'items', 'one by one', 'list'])
    # Flow / pipeline diagram
    is_flow = any(kw in visual_lower for kw in ['diagram', 'pipeline', 'phase', 'flow chart', 'flow diagram'])
    # Decision matrix
    is_decision = any(kw in visual_lower for kw in ['decision matrix', 'approve', 'rerun', 'four-card', 'four options'])
    # Table
    is_table = any(kw in visual_lower for kw in ['table', 'decision table', 'comparison'])
    # File icons
    is_files = any(kw in visual_lower for kw in ['file icon', 'deliverable', '.docx', '.pptx', '.xlsx'])

    if has_code and not is_flow:
        # Render code block from raw text (preserved before TTS cleaning)
        raw = scene.get('raw', narration)
        code_lines_raw = [l for l in raw.split('\n') if l.strip() and not l.startswith('**')]
        code_text = []
        in_fence = False
        for line in code_lines_raw:
            stripped = line.strip()
            if stripped.startswith('```'):
                in_fence = not in_fence
                continue
            if in_fence or any(stripped.startswith(k) for k in ['git ','python ','pip ','nuclei','nmap ','/skill','cd ','mkdir']):
                code_text.append(stripped)
        if code_text:
            content_y = _code_block(draw, '\n'.join(code_text[:8]), content_x, content_y, content_w - 40)
            content_y += 40  # Gap after code block

        # Body text below code
        body = [l for l in lines if l not in code_text and not l.startswith('```')]
        if body:
            content_y = _text_box(draw, ' '.join(body), content_x, content_y, content_w, BODY_F, LIGHT)

    elif is_list:
        # Render as checklist / bullet cards
        items = []
        current = []
        for line in lines:
            if line.startswith(('First', 'Second', 'Third', 'Fourth', 'Finally', 'And finally',
                                'Step', '—')):
                if current:
                    items.append(' '.join(current))
                # Clean up the prefix
                cleaned = re.sub(r'^(First,?|Second,?|Third,?|Fourth,?|Finally,?|And finally,?|Step\s+\w+[,:]?\s*)',
                                 '', line)
                current = [cleaned]
            else:
                current.append(line)
        if current:
            items.append(' '.join(current))

        if items:
            content_y = _checklist(draw, items, content_x, content_y, content_w)

    elif is_flow:
        # Draw pipeline flow diagram
        content_y = _pipeline_flow(draw, WIDTH // 2, content_y + 20)
        # Brief body text below
        body = ' '.join([l for l in lines if len(l) > 30][:3])
        if body:
            _text_box(draw, body[:300], content_x, content_y, content_w, BODY_F, LIGHT)

    elif is_decision:
        # Draw decision matrix
        content_y = _decision_matrix(draw, content_x, content_y + 20, content_w)
        body = ' '.join([l for l in lines if len(l) > 30][:2])
        if body:
            _text_box(draw, body[:300], content_x, content_y + 10, content_w, BODY_F, LIGHT)

    else:
        # Generic body text
        body = narration[:500]
        if body:
            content_y = _text_box(draw, body, content_x, content_y, content_w, BODY_F, LIGHT, spacing=10)

    # If visual direction is present and different from narration body, show it at the bottom
    if visual:
        vy = HEIGHT - 60
        _red_bar(draw, vy - 15, 80, 2)
        _text_box(draw, f'  {visual}', content_x, vy, content_w - 40, SMALL_F, MED, spacing=4)

    img.save(out_path)


# ── Main entry point ──

def generate_slides(scenes, output_dir):
    """Generate all slides for a list of parsed scenes."""
    from pathlib import Path
    slide_dir = Path(output_dir) / 'slides'
    slide_dir.mkdir(parents=True, exist_ok=True)

    for scene in scenes:
        scene_id = str(scene['id']).zfill(2) if scene['id'] != 'OUTRO' else 'outro'
        png_path = slide_dir / f'scene_{scene_id}.png'

        print(f'  Scene {scene_id}: ', end='', flush=True)

        if scene['id'] == '1' or scene.get('title', '') == 'INTRO':
            render_intro(scene, str(png_path))
            print('intro card')
        elif scene['id'] == 'OUTRO':
            render_outro(scene, str(png_path))
            print('outro card')
        else:
            render_content_slide(scene, str(png_path))
            print('content slide')
