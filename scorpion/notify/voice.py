"""Local text-to-speech for Scorpion.ai.

The agent likes to "say" its findings out loud and attach a spoken voice note
to Telegram alerts. There is no cloud TTS here and no third-party package: this
module shells out to whatever speech engine happens to be installed on the
operator's box, detected with :func:`shutil.which`, and degrades to a clean
no-op when nothing is available (a headless server with no audio stack must
never error).

Detection order (first match wins):

    * ``piper``      — a neural TTS; needs a voice model (``SCORPION_PIPER_MODEL``
                       or ``PIPER_MODEL`` env var, or ``cfg.piper_model``).
    * ``espeak-ng`` / ``espeak`` — renders a WAV; converted to OGG/Opus with
                       ``ffmpeg`` when that is also present.
    * ``say``        — macOS built-in TTS.

Public surface:

    Voice(cfg).engine_name  -> str | None     (which engine would be used)
    Voice(cfg).tts(text)    -> bytes | None    (synthesize to OGG/WAV bytes)
    Voice(cfg).speak(text)  -> bool            (play locally, best effort)
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Optional, Tuple

log = logging.getLogger("scorpion.notify.voice")

# players that can render an audio file through the default device
_PLAYERS = ("aplay", "paplay", "afplay", "play")
# engines that can speak straight to the audio device (no file round-trip)
_DIRECT_SPEAKERS = ("espeak-ng", "espeak", "say")


class Voice:
    """A best-effort wrapper around a local speech engine."""

    def __init__(self, cfg: Any, timeout: float = 20.0):
        self.cfg = cfg
        self.enabled = bool(getattr(cfg, "voice_enabled", True))
        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError):
            self.timeout = 20.0
        self.piper_model = str(
            getattr(cfg, "piper_model", "")
            or os.environ.get("SCORPION_PIPER_MODEL", "")
            or os.environ.get("PIPER_MODEL", "")
            or "")

    # -- detection ---------------------------------------------------------
    def _which(self, name: str) -> Optional[str]:
        try:
            return shutil.which(name)
        except Exception:  # noqa: BLE001 - detection must never raise
            return None

    def _pick_engine(self) -> Tuple[Optional[str], Optional[str]]:
        """Return ``(binary_name, kind)`` for the preferred engine, or (None, None)."""
        if self.piper_model and self._which("piper"):
            return "piper", "piper"
        for cand in ("espeak-ng", "espeak"):
            if self._which(cand):
                return cand, "espeak"
        if self._which("say"):
            return "say", "say"
        return None, None

    @property
    def engine_name(self) -> Optional[str]:
        """Name of the engine that would be used, or None if none is installed."""
        name, _ = self._pick_engine()
        return name

    @property
    def available(self) -> bool:
        """True when voice is enabled *and* a usable engine is present."""
        return self.enabled and self.engine_name is not None

    # -- synthesis to bytes ------------------------------------------------
    def tts(self, text: str) -> Optional[bytes]:
        """Render ``text`` to OGG/Opus (preferred) or WAV bytes.

        Returns None when no engine is installed or synthesis fails. Independent
        of the audio device: this only writes to a temp file and reads it back,
        so it works on a headless server.
        """
        body = text if isinstance(text, str) else str(text or "")
        if not body.strip():
            return None
        name, kind = self._pick_engine()
        if not name:
            return None
        try:
            if kind == "piper":
                return self._tts_piper(body)
            if kind == "espeak":
                return self._tts_espeak(name, body)
            if kind == "say":
                return self._tts_say(body)
        except subprocess.TimeoutExpired:
            log.warning("voice tts via %s timed out", name)
        except Exception as exc:  # noqa: BLE001 - must never raise
            log.warning("voice tts via %s failed: %s", name, exc)
        return None

    def _tts_piper(self, text: str) -> Optional[bytes]:
        if not self.piper_model:
            return None
        with tempfile.TemporaryDirectory() as td:
            wav = os.path.join(td, "out.wav")
            self._run(["piper", "--model", self.piper_model,
                       "--output_file", wav], stdin=text)
            return self._read_best(wav, td)

    def _tts_espeak(self, binary: str, text: str) -> Optional[bytes]:
        with tempfile.TemporaryDirectory() as td:
            wav = os.path.join(td, "out.wav")
            self._run([binary, "-w", wav, text])
            return self._read_best(wav, td)

    def _tts_say(self, text: str) -> Optional[bytes]:
        with tempfile.TemporaryDirectory() as td:
            wav = os.path.join(td, "out.wav")
            try:
                self._run(["say", "-o", wav, "--file-format=WAVE",
                           "--data-format=LEI16@22050", text])
            except Exception:  # noqa: BLE001 - some 'say' builds differ; fall back
                aiff = os.path.join(td, "out.aiff")
                self._run(["say", "-o", aiff, text])
                return self._read_best(aiff, td)
            return self._read_best(wav, td)

    def _read_best(self, wav_path: str, td: str) -> Optional[bytes]:
        """Convert to OGG when ffmpeg is present, else return the raw bytes."""
        if not os.path.exists(wav_path) or os.path.getsize(wav_path) == 0:
            return None
        ogg = self._maybe_ffmpeg_to_ogg(wav_path, td)
        path = ogg or wav_path
        try:
            with open(path, "rb") as fh:
                return fh.read()
        except OSError as exc:
            log.warning("voice: could not read synthesized audio: %s", exc)
            return None

    def _maybe_ffmpeg_to_ogg(self, wav_path: str, td: str) -> Optional[str]:
        if not self._which("ffmpeg"):
            return None
        ogg = os.path.join(td, "out.ogg")
        try:
            self._run(["ffmpeg", "-y", "-i", wav_path,
                       "-c:a", "libopus", "-b:a", "32k", ogg])
        except Exception as exc:  # noqa: BLE001 - ogg is optional, WAV is fine
            log.warning("voice: ffmpeg OGG conversion failed: %s", exc)
            return None
        if os.path.exists(ogg) and os.path.getsize(ogg) > 0:
            return ogg
        return None

    # -- local playback ----------------------------------------------------
    def speak(self, text: str) -> bool:
        """Say ``text`` out loud on the local machine. Best effort; never raises."""
        if not self.enabled:
            return False
        body = text if isinstance(text, str) else str(text or "")
        if not body.strip():
            return False
        try:
            return self._speak(body)
        except subprocess.TimeoutExpired:
            log.warning("voice speak timed out")
        except Exception as exc:  # noqa: BLE001 - playback must never raise
            log.warning("voice speak failed: %s", exc)
        return False

    def _speak(self, text: str) -> bool:
        # 1) engines that talk straight to the device
        for cand in _DIRECT_SPEAKERS:
            if self._which(cand):
                self._run([cand, text])
                return True
        # 2) synthesize then pipe through a player
        player = None
        for cand in _PLAYERS:
            if self._which(cand):
                player = cand
                break
        if not player:
            return False
        audio = self.tts(text)
        if not audio:
            return False
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "speak.wav")
            with open(path, "wb") as fh:
                fh.write(audio)
            self._run([player, path])
        return True

    # -- subprocess helper -------------------------------------------------
    def _run(self, cmd, stdin: Optional[str] = None) -> None:
        inp = stdin.encode("utf-8") if isinstance(stdin, str) else stdin
        subprocess.run(
            cmd,
            input=inp,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=self.timeout,
            check=True,
        )


__all__ = ["Voice"]
