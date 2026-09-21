#!/usr/bin/env python3
"""Generate a lo-fi ambient background track with warm harmonics. Royalty-free."""
import numpy as np
import soundfile as sf
import sys

SR = 24000

def sawtooth(freq, t, duty=0.5):
    """Warm sawtooth wave (rich harmonics)."""
    phase = (freq * t) % 1.0
    wave = 2.0 * ((phase / duty) % 1.0) - 1.0
    return wave

def lowpass(signal, cutoff, sr):
    """Simple low-pass filter for warmth."""
    RC = 1.0 / (2 * np.pi * cutoff)
    dt = 1.0 / sr
    alpha = dt / (RC + dt)
    filtered = np.zeros_like(signal)
    filtered[0] = signal[0]
    for i in range(1, len(signal)):
        filtered[i] = filtered[i-1] + alpha * (signal[i] - filtered[i-1])
    return filtered

def reverb(signal, delay_ms=80, decay=0.3, mix=0.3):
    """Simple delay-based reverb."""
    delay_samples = int(delay_ms / 1000 * SR)
    wet = np.zeros_like(signal)
    for i in range(delay_samples, len(signal)):
        wet[i] = signal[i] + decay * wet[i - delay_samples]
    return (1 - mix) * signal + mix * wet

def generate_ambient(duration_sec=600, output='bg.wav'):
    t = np.linspace(0, duration_sec, int(SR * duration_sec), endpoint=False)
    audio = np.zeros_like(t)

    # Chord progression: Fmaj7 → Am7 → Dm7 → Cmaj7 (warm, corporate)
    chords = [
        [174.61, 220.00, 261.63, 349.23],  # Fmaj7: F3 A3 C4 E4
        [220.00, 261.63, 329.63, 440.00],  # Am7:   A3 C4 E4 G4
        [293.66, 349.23, 440.00, 523.25],  # Dm7:   D4 F4 A4 C5
        [261.63, 329.63, 392.00, 493.88],  # Cmaj7: C4 E4 G4 B4
    ]
    chord_dur = duration_sec / len(chords)

    for ci, freqs in enumerate(chords):
        start = int(ci * chord_dur * SR)
        end = int((ci + 1) * chord_dur * SR)
        t_seg = t[start:end]

        # Arpeggiated chord — each note fades in/out gently
        for i, f in enumerate(freqs):
            offset = i * 0.15  # Slight stagger between notes
            env = np.exp(-(t_seg - offset) * 0.3) * 0.7  # Gentle decay
            env = np.maximum(env, 0.15)  # Sustain floor

            # Richer wave — blend sawtooth + filtered sine
            saw = sawtooth(f, t_seg - offset)
            saw = lowpass(saw, cutoff=f * 2.5, sr=SR)  # Warm lowpass
            note = 0.08 * env * saw
            audio[start:end] += note

        # Pad layer — very soft filtered saw for warmth
        pad = np.zeros_like(t_seg)
        for f in freqs[:3]:  # Just the triad for pad
            pad += 0.03 * np.sin(2 * np.pi * f * t_seg)  # Pure sine pad
        pad = lowpass(pad, cutoff=300, sr=SR)
        audio[start:end] += pad

    # Subtle LFO movement for life
    tremolo = 0.9 + 0.1 * np.sin(2 * np.pi * 0.15 * t)  # 0.15 Hz tremolo
    audio = audio * tremolo

    # Add gentle noise texture
    noise = np.random.normal(0, 0.002, len(t))
    audio += noise

    # Reverb for space
    audio = reverb(audio, delay_ms=100, decay=0.4, mix=0.25)

    # Fade in/out
    fade_len = int(SR * 4)
    audio[:fade_len] *= np.linspace(0, 1, fade_len)
    audio[-fade_len:] *= np.linspace(1, 0, fade_len)

    # Normalise to -18dB (clearly audible but not loud)
    peak = np.max(np.abs(audio))
    if peak > 0:
        audio = audio / peak * 0.35  # -9dB peak = clearly audible under narration

    sf.write(output, audio.astype(np.float32), SR)
    import os
    print(f'Generated: {output} ({os.path.getsize(output)} bytes, {duration_sec}s, {20*np.log10(np.sqrt(np.mean(audio**2))+1e-10):.1f}dB RMS)')
    return output

if __name__ == '__main__':
    dur = float(sys.argv[1]) if len(sys.argv) > 1 else 600
    out = sys.argv[2] if len(sys.argv) > 2 else 'bg.wav'
    generate_ambient(dur, output=out)
