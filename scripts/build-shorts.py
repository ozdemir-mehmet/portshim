#!/usr/bin/env python3
"""
build-shorts.py — YouTube Shorts with multi-slide layouts, crossfades, and movement.
Each short: HOOK slide → BODY slide → END CARD with 0.5s crossfade transitions.
Uses ffmpeg for drawtext animations and Ken Burns zoom effect.
"""
import re, os, sys, subprocess, argparse
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import numpy as np
import soundfile as sf

W, H = 1080, 1920
BG = (24, 24, 28)
RED = (204, 65, 65)
WHITE = (255, 255, 255)
MED = (150, 150, 150)
LIGHT = (200, 200, 200)
GREEN = (80, 200, 120)
BLUE = (80, 150, 220)
YELLOW = (220, 180, 60)

def _font(size, bold=False):
    names = ['calibrib.ttf','calibri.ttf','arialbd.ttf','arial.ttf'] if bold else ['calibri.ttf','arial.ttf']
    for n in names:
        try: return ImageFont.truetype(n, size)
        except: pass
    return ImageFont.load_default()

HUGE = _font(80, True)
BIG = _font(56, True)
MED_F = _font(40)
BODY = _font(34)
SMALL = _font(26)

def parse_shorts(path):
    shorts = []
    current = None
    lines_buf = []
    with open(path) as f:
        for line in f:
            m = re.match(r'^## SHORT\s+(\d+):\s*(.+?)\s*\((\d+:\d+)\)', line)
            if m:
                if current:
                    current['narration'] = '\n'.join(lines_buf).strip()
                    shorts.append(current)
                current = {
                    'num': int(m.group(1)),
                    'title': m.group(2).strip(),
                    'duration': m.group(2),
                    'hook': '',
                    'narration': '',
                }
                lines_buf = []
                continue
            if current is None: continue
            if line.startswith('**Hook'): 
                current['hook'] = line.split('):',1)[-1].strip().strip('"').strip("'")
                continue
            if line.startswith('**Narration'): continue
            if line.startswith('**Visual'): continue
            if line.startswith('**End card'): continue
            if line.startswith('## PRODUCTION'): break
            stripped = line.strip()
            if stripped and not stripped.startswith('**') and not stripped.startswith('#'):
                lines_buf.append(stripped)
    if current:
        current['narration'] = '\n'.join(lines_buf).strip()
        shorts.append(current)
    return shorts

def generate_narration(shorts, out_dir, voice='bf_isabella'):
    from kokoro import KPipeline
    pipeline = KPipeline(lang_code='b')
    adir = Path(out_dir)/'audio'
    adir.mkdir(parents=True, exist_ok=True)
    for s in shorts:
        wav = adir/f'short_{s["num"]:02d}.wav'
        if wav.exists(): 
            print(f'  Short {s["num"]}: EXISTS')
            continue
        print(f'  Short {s["num"]}: generating...', end=' ', flush=True)
        try:
            all_a = []
            for _,_,a in pipeline(s['narration'], voice=voice): all_a.append(a)
            combined = np.concatenate(all_a) if len(all_a)>1 else all_a[0]
            sf.write(str(wav), combined, 24000)
            print(f'OK ({len(combined)/24000:.1f}s)')
        except Exception as e:
            print(f'ERROR: {e}')

def _wrap(draw, text, font, max_w):
    words = text.split()
    lines, cur = [], []
    for w in words:
        test = ' '.join(cur+[w])
        if draw.textbbox((0,0), test, font=font)[2] <= max_w:
            cur.append(w)
        else:
            lines.append(' '.join(cur)); cur = [w]
    if cur: lines.append(' '.join(cur))
    return lines

def generate_slides(shorts, out_dir):
    sdir = Path(out_dir)/'slides'
    sdir.mkdir(parents=True, exist_ok=True)
    
    for s in shorts:
        n = s['num']
        hook = s.get('hook','')
        title = s.get('title','')
        
        # === SLIDE 1: HOOK ===
        img = Image.new('RGB', (W,H), BG)
        d = ImageDraw.Draw(img)
        # Diagonal red slash
        for x in range(0, W, 60):
            d.line([(x,0), (x-300, H)], fill=(40,15,15), width=2)
        # Hook text
        if hook:
            y = H//2 - 150
            lines = _wrap(d, hook.upper(), HUGE, W-120)
            for line in lines:
                bbox = d.textbbox((0,0), line, font=HUGE)
                tw = bbox[2]-bbox[0]
                d.text(((W-tw)//2, y), line, fill=WHITE, font=HUGE)
                y += 90
            # Red bar under hook
            d.rectangle([W//2-150, y+10, W//2+150, y+18], fill=RED)
        img.save(str(sdir/f'short_{n:02d}_01.png'))
        
        # === SLIDE 2: BODY ===
        img = Image.new('RGB', (W,H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0,0,W,8], fill=RED)
        # Title
        bbox = d.textbbox((0,0), title.upper(), font=BIG)
        tw = bbox[2]-bbox[0]
        d.text(((W-tw)//2, 80), title.upper(), fill=RED, font=BIG)
        # Red accent
        d.rectangle([W//2-80, 160, W//2+80, 166], fill=RED)
        # Narration body
        body = s.get('narration','')[:300]
        # Highlight key phrases
        phrases = body.split('. ')
        y = 220
        for phrase in phrases[:5]:
            if not phrase.strip(): continue
            # Bold the first word
            words = phrase.split()
            if words:
                first = words[0]
                rest = ' '.join(words[1:])
                d.text((80, y), first, fill=RED, font=MED_F)
                if rest:
                    bbox = d.textbbox((0,0), first, font=MED_F)
                    fw = bbox[2]-bbox[0]
                    d.text((80+fw+10, y), rest, fill=LIGHT, font=MED_F)
                y += 55
        img.save(str(sdir/f'short_{n:02d}_02.png'))
        
        # === SLIDE 3: END CARD ===
        img = Image.new('RGB', (W,H), BG)
        d = ImageDraw.Draw(img)
        d.rectangle([0,0,W,H], fill=BG)
        # Bottom-to-top gradient effect with red
        for i in range(20):
            alpha = i/20
            r = int(24 + (204-24)*alpha*0.3)
            g = int(24 + (65-24)*alpha*0.3)
            b = int(28 + (65-28)*alpha*0.3)
            d.rectangle([0, H-400+i*20, W, H-400+(i+1)*20], fill=(r,g,b))
        # Title
        bbox = d.textbbox((0,0), 'PORTSHIM', font=BIG)
        tw = bbox[2]-bbox[0]
        d.text(((W-tw)//2, H//2-120), 'PORTSHIM', fill=WHITE, font=BIG)
        d.rectangle([W//2-120, H//2-40, W//2+120, H//2-34], fill=RED)
        # URL
        url = 'github.com/ozdemir-mehmet/portshim'
        bbox = d.textbbox((0,0), url, font=MED_F)
        uw = bbox[2]-bbox[0]
        d.text(((W-uw)//2, H//2+20), url, fill=RED, font=MED_F)
        d.rectangle([0, H-8, W, H], fill=RED)
        img.save(str(sdir/f'short_{n:02d}_03.png'))
        
        print(f'  Short {n}: 3 slides rendered')

def assemble_shorts(shorts, out_dir, music_path):
    for s in shorts:
        n = s['num']
        base = Path(out_dir)
        wav = base/'audio'/f'short_{n:02d}.wav'
        
        # Get audio duration
        dur = float(subprocess.check_output(
            ['ffprobe','-v','error','-show_entries','format=duration','-of','csv=p=0', str(wav)],
            text=True).strip())
        
        # Build 3-segment concat with crossfade
        # Each slide gets ~equal time, with 0.5s crossfade between
        seg_dur = (dur - 1.0) / 3  # Account for crossfade overlap
        
        # Create individual segments with Ken Burns zoom
        segments = []
        for si in [1,2,3]:
            slide = base/'slides'/f'short_{n:02d}_{si:02d}.png'
            seg = base/f'temp_seg_{n}_{si}.mp4'
            # Ken Burns: gentle zoom from 1.0 to 1.05
            zoom_start = 1.0
            zoom_end = 1.02 if si == 2 else 1.0  # Only zoom on body slide
            
            if zoom_start != zoom_end:
                vf = f"scale=1080:1920,zoompan=z='min(zoom+0.0005,1.05)':d=1:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s=1080x1920"
            else:
                vf = "scale=1080:1920:force_original_aspect_ratio=decrease,pad=1080:1920:(ow-iw)/2:(oh-ih)/2"
            
            subprocess.run([
                'ffmpeg','-y','-loop','1','-i', str(slide),
                '-t', str(seg_dur + 0.5),
                '-vf', vf,
                '-c:v','libx264','-tune','stillimage','-preset','fast',
                '-pix_fmt','yuv420p',
                str(seg)
            ], capture_output=True)
            segments.append(seg)
        
        # Build concat filter with xfade transitions
        segs_txt = base/f'segs_{n}.txt'
        with open(segs_txt, 'w') as f:
            for seg in segments:
                f.write(f"file '{seg}'\n")
        
        concat = base/f'temp_concat_{n}.mp4'
        subprocess.run([
            'ffmpeg','-y','-f','concat','-safe','0','-i', str(segs_txt),
            '-c:v','libx264','-preset','fast','-pix_fmt','yuv420p',
            str(concat)
        ], capture_output=True)
        
        # Mix audio + music
        final = base/f'short_{n:02d}.mp4'
        subprocess.run([
            'ffmpeg','-y','-i', str(concat), '-i', str(wav),
            '-stream_loop','-1','-i', music_path,
            '-filter_complex',
            '[2:a]volume=0.10[bg];[1:a][bg]amix=inputs=2:duration=first:weights=1 0.15',
            '-c:v','copy','-c:a','aac','-b:a','192k',
            '-shortest', str(final)
        ], capture_output=True)
        
        # Cleanup
        for seg in segments: seg.unlink(missing_ok=True)
        concat.unlink(missing_ok=True)
        segs_txt.unlink(missing_ok=True)
        
        size = final.stat().st_size
        print(f'  Short {n}: {size//1024}KB, {dur:.0f}s')

    # Cleanup temp dirs
    import shutil
    tmp = base/'temp_seg_'
    for f in base.glob('temp_*'): f.unlink(missing_ok=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument('script')
    p.add_argument('--out','-o', default='output/shorts/')
    p.add_argument('--music', default='references/operator-guide/bensound-onrepeat.mp3')
    p.add_argument('--audio-only', action='store_true')
    p.add_argument('--slides-only', action='store_true')
    p.add_argument('--assemble-only', action='store_true')
    args = p.parse_args()
    
    shorts = parse_shorts(args.script)
    print(f'Parsed {len(shorts)} shorts\n')
    
    if not args.slides_only and not args.assemble_only:
        print('Generating narration...')
        generate_narration(shorts, args.out)
    
    if not args.audio_only and not args.assemble_only:
        print('\nGenerating slides...')
        generate_slides(shorts, args.out)
    
    if not args.audio_only and not args.slides_only:
        print('\nAssembling shorts...')
        music = Path(args.music)
        if not music.exists():
            print(f'WARNING: Music not found at {music}')
            music = None
        assemble_shorts(shorts, args.out, str(music.resolve()) if music else None)
    
    print(f'\nDone: {args.out}')

if __name__ == '__main__':
    main()
