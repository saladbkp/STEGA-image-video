import os
import subprocess
import threading
import re
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk


BASE_DIR = Path(__file__).resolve().parent
STEGO_BIN = BASE_DIR / "stego"
DECODE_AFTER_ATTR = "user.decode_after"


def append_log(widget: scrolledtext.ScrolledText, text: str) -> None:
    widget.configure(state="normal")
    widget.insert(tk.END, text + "\n")
    widget.see(tk.END)
    widget.configure(state="disabled")


def clear_log(widget: scrolledtext.ScrolledText) -> None:
    widget.configure(state="normal")
    widget.delete("1.0", tk.END)
    widget.configure(state="disabled")


def pick_file(var: tk.StringVar, save: bool = False, **kwargs) -> None:
    picker = filedialog.asksaveasfilename if save else filedialog.askopenfilename
    path = picker(**kwargs)
    if path:
        var.set(path)


def _run_cmd(args):
    return subprocess.run(args, cwd=BASE_DIR, capture_output=True, text=True)


def run_stego(args, log_widget: scrolledtext.ScrolledText) -> bool:
    if not STEGO_BIN.exists():
        messagebox.showerror("stego binary missing", f"Could not find {STEGO_BIN}. Build it before running the GUI.")
        return False

    cmd = [str(STEGO_BIN)] + args
    append_log(log_widget, "$ " + " ".join(cmd))

    result = _run_cmd(cmd)

    output = (result.stdout or "") + (result.stderr or "")
    append_log(log_widget, output.strip() if output.strip() else "(no output)")

    if result.returncode != 0:
        messagebox.showerror("Command failed", f"stego exited with code {result.returncode}")
        return False
    return True


def run_stego_stream(args, log_widget: scrolledtext.ScrolledText, progress_var: tk.DoubleVar, on_done):
    """Run stego streaming output; update log/progress. Calls on_done(success) on finish."""
    if not STEGO_BIN.exists():
        messagebox.showerror("stego binary missing", f"Could not find {STEGO_BIN}. Build it before running the GUI.")
        return

    cmd = [str(STEGO_BIN)] + args
    append_log(log_widget, "$ " + " ".join(cmd))
    progress_var.set(0)

    def worker():
        success = False
        try:
            proc = subprocess.Popen(cmd, cwd=BASE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            combined = []
            if proc.stdout:
                for line in proc.stdout:
                    combined.append(line)
                    line_strip = line.rstrip()
                    log_widget.after(0, append_log, log_widget, line_strip)
                    m = re.search(r"(\d+)%", line_strip)
                    if m:
                        try:
                            pct = float(m.group(1))
                            log_widget.after(0, progress_var.set, pct)
                        except ValueError:
                            pass
            proc.wait()
            success = proc.returncode == 0
        except Exception as exc:
            log_widget.after(0, append_log, log_widget, f"[error] {exc}")
            success = False
        finally:
            log_widget.after(0, progress_var.set, 0)
            log_widget.after(0, on_done, success)

    threading.Thread(target=worker, daemon=True).start()


def run_stego_capture(args):
    """Run stego without GUI log; return (ok, combined_output)."""
    if not STEGO_BIN.exists():
        return False, "stego binary missing"
    cmd = [str(STEGO_BIN)] + args
    result = _run_cmd(cmd)
    output = (result.stdout or "") + (result.stderr or "")
    return result.returncode == 0, output


def parse_decode_after(value: str):
    value = value.strip()
    if not value:
        return None, None
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(value, fmt), None
        except ValueError:
            continue
    return None, "Use format YYYY-MM-DD HH:MM or YYYY-MM-DD HH:MM:SS"


def enforce_decode_after(value: str) -> bool:
    """Return True if decode is allowed for the given value."""
    decode_at, err = parse_decode_after(value)
    if err:
        messagebox.showerror("Invalid decode time", err)
        return False
    if decode_at and datetime.now() < decode_at:
        messagebox.showwarning("Too early", f"Decoding allowed after {decode_at}")
        return False
    return True


def validate_decode_after_input(value: str) -> bool:
    _, err = parse_decode_after(value)
    if err:
        messagebox.showerror("Invalid decode time", err)
        return False
    return True


def store_decode_after_metadata(path: str, value: str, log_widget=None) -> None:
    value = value.strip()
    if not value:
        return
    try:
        os.setxattr(path, DECODE_AFTER_ATTR, value.encode())
        if log_widget:
            append_log(log_widget, f"[decode-after] saved '{value}' to metadata")
    except Exception as exc:  # pragma: no cover - best-effort
        if log_widget:
            append_log(log_widget, f"[warn] could not save decode-after metadata: {exc}")


def read_decode_after_metadata(path: str, log_widget=None) -> str:
    try:
        raw = os.getxattr(path, DECODE_AFTER_ATTR)
        val = raw.decode(errors="ignore") if isinstance(raw, (bytes, bytearray)) else str(raw)
        val = val.strip()
        if val and log_widget:
            append_log(log_widget, f"[decode-after] found stored time '{val}'")
        return val
    except OSError:
        return ""
    except Exception as exc:  # pragma: no cover - best-effort
        if log_widget:
            append_log(log_widget, f"[warn] could not read decode-after metadata: {exc}")
        return ""


def resolve_decode_after_value(path: str, user_value: str, log_widget=None) -> str:
    meta_val = read_decode_after_metadata(path, log_widget)
    user_val = user_value.strip()
    if meta_val:
        if user_val and user_val != meta_val and log_widget:
            append_log(log_widget, "[decode-after] using stored metadata value; user entry ignored")
        return meta_val
    return user_val


def parse_image_metrics(cover, stego):
    ok, out = run_stego_capture(["metrics", cover, stego])
    if not ok:
        return False, out.strip()
    psnr = ""
    ssim = ""
    for line in out.splitlines():
        if line.lower().startswith("psnr"):
            psnr = line.split(":")[-1].strip()
        if line.lower().startswith("ssim"):
            ssim = line.split(":")[-1].strip()
    metrics_text = f"PSNR {psnr}, SSIM {ssim}".strip()
    return True, metrics_text if metrics_text.strip() else out.strip()


def parse_video_metrics(cover, stego):
    ok, out = run_stego_capture(["video_metrics", cover, stego,"--vmaf"])
    if not ok:
        return False, out.strip()
    return parse_video_metrics_from_output(out)


def parse_video_metrics_from_output(out: str):
    lines = out.splitlines()
    # print(lines)
    psnr = ""
    ssim = ""
    sync = ""
    vmaf = ""
    fps = ""
    frames = ""
    vmaf_re = re.compile(r"video vmaf.*?:\s*([0-9.]+)", re.IGNORECASE)
    fallback_vmaf_re = re.compile(r"\bvmaf[^:]*:\s*([0-9.]+)", re.IGNORECASE)
    fps_re = re.compile(r"([0-9]+(?:\.[0-9]+)?)\s*fps", re.IGNORECASE)
    frames_re = re.compile(r"\b([0-9]+)\s*frames\b", re.IGNORECASE)
    frames_used_re = re.compile(r"frames used:\s*([0-9]+)", re.IGNORECASE)
    frames_fps_line_re = re.compile(r"\b([0-9]+)\s*frames\b.*?([0-9]+(?:\.[0-9]+)?)\s*fps", re.IGNORECASE)
    for line in lines:
        low = line.lower()
        if low.startswith("video psnr"):
            psnr = line.split(":")[-1].strip()
        elif low.startswith("video ssim"):
            ssim = line.split(":")[-1].strip()
        elif "sync error" in low:
            sync = line.split(":")[-1].strip()
        if not frames or not fps:
            m_frames_fps = frames_fps_line_re.search(line)
            if m_frames_fps:
                if not frames:
                    frames = m_frames_fps.group(1)
                if not fps:
                    fps = m_frames_fps.group(2)
        if not frames:
            m_frames = frames_used_re.search(line) or frames_re.search(line)
            if m_frames:
                frames = m_frames.group(1)
        if not vmaf:
            m_vmaf = vmaf_re.search(line) or fallback_vmaf_re.search(line)
            if m_vmaf:
                vmaf = m_vmaf.group(1)
        if not fps:
            m_fps = fps_re.search(line)
            if m_fps:
                fps = m_fps.group(1)
    text = ", ".join(
        [
            val
            for val in [
                f"VMAF {vmaf}" if vmaf else "",
                f"PSNR {psnr}" if psnr else "",
                f"SSIM {ssim}" if ssim else "",
                f"Frames {frames}" if frames else "",
                f"FPS {fps}" if fps else "",
                f"Sync {sync}" if sync else "",
            ]
            if val
        ]
    )
    return True, text if text else out.strip()


def run_video_metrics_async(cover, stego, log_widget, metrics_var, progress_bar, progress_var, on_complete=None):
    metrics_var.set("Metrics: calculating...")

    def worker():
        cmd = [str(STEGO_BIN), "video_metrics", cover, stego,"--vmaf"]
        proc = subprocess.Popen(cmd, cwd=BASE_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        combined_lines = []
        last_pct = 0.0
        if proc.stdout:
            for line in proc.stdout:
                # print(line)
                combined_lines.append(line)
                line_strip = line.rstrip()
                log_widget.after(0, append_log, log_widget, line_strip)
                m = re.search(r"(\d+)%", line_strip)
                if m:
                    try:
                        pct = float(m.group(1))
                        last_pct = pct
                        log_widget.after(0, progress_var.set, pct)
                    except ValueError:
                        pass
        proc.wait()
        log_widget.after(0, progress_var.set, 100.0 if last_pct < 100 else last_pct)

        def finish():
            progress_bar.configure(mode="determinate")
            if proc.returncode == 0:
                ok, text = parse_video_metrics_from_output("".join(combined_lines))
                if ok:
                    metrics_var.set(f"Metrics: {text}")
                    append_log(log_widget, "[metrics] " + text)
                else:
                    metrics_var.set("Metrics: failed (see log)")
                    append_log(log_widget, "[metrics] " + text)
            else:
                metrics_var.set("Metrics: failed (see log)")
                append_log(log_widget, "[metrics] video_metrics failed")
            if on_complete:
                on_complete()
            progress_var.set(0)

        log_widget.after(0, finish)

    threading.Thread(target=worker, daemon=True).start()


def build_image_section(root, log_widget):
    frame = tk.Frame(root)
    frame.columnconfigure(1, weight=1)

    cover_var = tk.StringVar()
    stego_var = tk.StringVar()
    message_file_var = tk.StringVar()
    password_var = tk.StringVar()
    decode_after_var = tk.StringVar()
    metrics_var = tk.StringVar(value="Metrics: —")

    tk.Label(frame, text="Cover image").grid(row=0, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=cover_var).grid(row=0, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(cover_var, filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp *.tiff"), ("All files", "*.*")])).grid(row=0, column=2, padx=4, pady=2)

    tk.Label(frame, text="Output stego").grid(row=1, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=stego_var).grid(row=1, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Save as", command=lambda: pick_file(stego_var, save=True, defaultextension=".png", filetypes=[("PNG", "*.png"), ("All files", "*.*")])).grid(row=1, column=2, padx=4, pady=2)

    tk.Label(frame, text="Message file (optional)").grid(row=2, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=message_file_var).grid(row=2, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(message_file_var, filetypes=[("Text", "*.txt"), ("All files", "*.*")])).grid(row=2, column=2, padx=4, pady=2)

    tk.Label(frame, text="Or type message").grid(row=3, column=0, sticky="nw", padx=4, pady=2)
    message_box = scrolledtext.ScrolledText(frame, height=4)
    message_box.grid(row=3, column=1, columnspan=2, sticky="ew", padx=4, pady=2)

    tk.Label(frame, text="Password (optional for encryption)").grid(row=4, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=password_var, show="*").grid(row=4, column=1, sticky="ew", padx=4, pady=2)

    tk.Label(frame, text="Decode after (YYYY-MM-DD HH:MM)").grid(row=5, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=decode_after_var).grid(row=5, column=1, sticky="ew", padx=4, pady=2)

    def do_embed():
        cover = cover_var.get().strip()
        stego = stego_var.get().strip()
        if not cover or not stego:
            messagebox.showwarning("Missing paths", "Pick a cover image and an output path.")
            return
        if not validate_decode_after_input(decode_after_var.get()):
            return

        message_file = message_file_var.get().strip()
        message_text = message_box.get("1.0", tk.END).strip()

        if message_file:
            payload_arg = message_file
        elif message_text:
            payload_arg = message_text
        else:
            messagebox.showwarning("Missing message", "Provide text or select a message file.")
            return

        password = password_var.get().strip()
        if password:
            args = ["adaptive_encrypt_embed", cover, stego, payload_arg, password]
        else:
            args = ["adaptive_embed", cover, stego, payload_arg]

        if run_stego(args, log_widget):
            store_decode_after_metadata(stego, decode_after_var.get(), log_widget)
            ok, metrics_text = parse_image_metrics(cover, stego)
            if ok:
                metrics_var.set(f"Metrics: {metrics_text}")
                append_log(log_widget, "[metrics] " + metrics_text)
            else:
                metrics_var.set("Metrics: failed (see log)")
                append_log(log_widget, "[metrics] " + metrics_text)
            messagebox.showinfo("Done", "Embedding finished.")

    def do_extract():
        stego = stego_var.get().strip()
        if not stego:
            messagebox.showwarning("Missing stego", "Pick a stego image to extract from.")
            return
        decode_after_value = resolve_decode_after_value(stego, decode_after_var.get(), log_widget)
        if not enforce_decode_after(decode_after_value):
            return
        password = password_var.get().strip()
        if password:
            args = ["adaptive_decrypt_extract", stego, password]
        else:
            args = ["adaptive_extract", stego]

        if run_stego(args, log_widget):
            messagebox.showinfo("Done", "Extraction finished. Check the log for the message.")

    tk.Button(frame, text="Embed", command=do_embed).grid(row=6, column=1, sticky="e", padx=4, pady=4)
    tk.Button(frame, text="Extract", command=do_extract).grid(row=6, column=2, sticky="w", padx=4, pady=4)

    tk.Label(frame, textvariable=metrics_var, anchor="w").grid(row=7, column=0, columnspan=3, sticky="ew", padx=4, pady=4)

    frame.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")


def build_video_text_section(root, log_widget):
    frame = tk.LabelFrame(root, text="Video ↔ Text")
    frame.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
    frame.columnconfigure(1, weight=1)
    metrics_var = tk.StringVar(value="Metrics: —")
    progress_var = tk.DoubleVar(value=0)

    cover_var = tk.StringVar()
    stego_var = tk.StringVar()
    msg_file_var = tk.StringVar()
    password_var = tk.StringVar()
    decode_after_var = tk.StringVar()
    metrics_btn = None  # set after creation

    tk.Label(frame, text="Cover video").grid(row=0, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=cover_var).grid(row=0, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(cover_var, filetypes=[("Video", "*.mp4 *.avi *.mov *.mkv"), ("All files", "*.*")])).grid(row=0, column=2, padx=4, pady=2)

    tk.Label(frame, text="Output stego").grid(row=1, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=stego_var).grid(row=1, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Save as", command=lambda: pick_file(stego_var, save=True, defaultextension=".avi", filetypes=[("AVI", "*.avi"), ("All files", "*.*")])).grid(row=1, column=2, padx=4, pady=2)

    tk.Label(frame, text="Message file (optional)").grid(row=2, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=msg_file_var).grid(row=2, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(msg_file_var, filetypes=[("Text", "*.txt"), ("All files", "*.*")])).grid(row=2, column=2, padx=4, pady=2)

    tk.Label(frame, text="Or type message").grid(row=3, column=0, sticky="nw", padx=4, pady=2)
    msg_box = scrolledtext.ScrolledText(frame, height=4)
    msg_box.grid(row=3, column=1, columnspan=2, sticky="ew", padx=4, pady=2)

    tk.Label(frame, text="Password (optional)").grid(row=4, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=password_var, show="*").grid(row=4, column=1, sticky="ew", padx=4, pady=2)

    tk.Label(frame, text="Decode after (YYYY-MM-DD HH:MM)").grid(row=5, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=decode_after_var).grid(row=5, column=1, sticky="ew", padx=4, pady=2)

    def do_embed():
        cover = cover_var.get().strip()
        stego = stego_var.get().strip()
        if not cover or not stego:
            messagebox.showwarning("Missing paths", "Pick a cover video and an output path.")
            return
        if not validate_decode_after_input(decode_after_var.get()):
            return

        msg_file = msg_file_var.get().strip()
        msg_text = msg_box.get("1.0", tk.END).strip()

        if msg_file:
            payload = msg_file
        elif msg_text:
            payload = msg_text
        else:
            messagebox.showwarning("Missing message", "Provide text or select a message file.")
            return

        password = password_var.get().strip()
        if password:
            args = ["video_encrypt_embed_text", cover, stego, payload, password]
        else:
            args = ["video_embed_text", cover, stego, payload]

        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def on_done(success):
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")
            if success:
                store_decode_after_metadata(stego, decode_after_var.get(), log_widget)
                messagebox.showinfo("Done", "Embedding finished.")
            else:
                messagebox.showerror("Failed", "Embedding failed. See log.")

        run_stego_stream(args, log_widget, progress_var, on_done)

    def do_extract():
        stego = stego_var.get().strip()
        if not stego:
            messagebox.showwarning("Missing stego", "Pick a stego video to extract from.")
            return
        decode_after_value = resolve_decode_after_value(stego, decode_after_var.get(), log_widget)
        if not enforce_decode_after(decode_after_value):
            return
        password = password_var.get().strip()
        if password:
            args = ["video_encrypt_extract_text", stego, password]
        else:
            args = ["video_extract_text", stego]

        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def on_done(success):
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")
            if success:
                messagebox.showinfo("Done", "Extraction finished. Check the log for the message.")
            else:
                messagebox.showerror("Failed", "Extraction failed. See log.")

        run_stego_stream(args, log_widget, progress_var, on_done)

    embed_btn = tk.Button(frame, text="Embed text", command=do_embed)
    embed_btn.grid(row=6, column=1, sticky="e", padx=4, pady=4)
    extract_btn = tk.Button(frame, text="Extract text", command=do_extract)
    extract_btn.grid(row=6, column=2, sticky="w", padx=4, pady=4)
    progress_bar = ttk.Progressbar(frame, variable=progress_var, maximum=100)
    progress_bar.grid(row=7, column=0, columnspan=3, sticky="ew", padx=4, pady=2)

    def run_metrics():
        cover = cover_var.get().strip()
        stego = stego_var.get().strip()
        if not cover or not stego:
            messagebox.showwarning("Missing paths", "Pick both cover and stego video for metrics.")
            return
        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def done():
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")

        run_video_metrics_async(cover, stego, log_widget, metrics_var, progress_bar, progress_var, on_complete=done)

    metrics_btn = tk.Button(frame, text="Run metrics", command=run_metrics)
    metrics_btn.grid(row=8, column=2, sticky="e", padx=4, pady=4)
    tk.Label(frame, textvariable=metrics_var, anchor="w").grid(row=8, column=0, columnspan=2, sticky="ew", padx=4, pady=4)

    # keep references for async updates
    frame._progress_bar = progress_bar  # type: ignore
    frame._progress_var = progress_var  # type: ignore
    frame._metrics_var = metrics_var    # type: ignore

    return metrics_var


def build_video_file_section(root, log_widget):
    frame = tk.LabelFrame(root, text="Video ↔ File")
    frame.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
    frame.columnconfigure(1, weight=1)
    metrics_var = tk.StringVar(value="Metrics: —")
    progress_var = tk.DoubleVar(value=0)

    cover_var = tk.StringVar()
    stego_var = tk.StringVar()
    secret_var = tk.StringVar()
    output_var = tk.StringVar()
    password_var = tk.StringVar()
    decode_after_var = tk.StringVar()
    metrics_btn = None  # set after creation

    tk.Label(frame, text="Cover video").grid(row=0, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=cover_var).grid(row=0, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(cover_var, filetypes=[("Video", "*.mp4 *.avi *.mov *.mkv"), ("All files", "*.*")])).grid(row=0, column=2, padx=4, pady=2)

    tk.Label(frame, text="Output stego").grid(row=1, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=stego_var).grid(row=1, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Save as", command=lambda: pick_file(stego_var, save=True, defaultextension=".avi", filetypes=[("AVI", "*.avi"), ("All files", "*.*")])).grid(row=1, column=2, padx=4, pady=2)

    tk.Label(frame, text="Secret file to embed").grid(row=2, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=secret_var).grid(row=2, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Browse", command=lambda: pick_file(secret_var, filetypes=[("All files", "*.*")])).grid(row=2, column=2, padx=4, pady=2)

    tk.Label(frame, text="Extract output file").grid(row=3, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=output_var).grid(row=3, column=1, sticky="ew", padx=4, pady=2)
    tk.Button(frame, text="Save as", command=lambda: pick_file(output_var, save=True, filetypes=[("All files", "*.*")])).grid(row=3, column=2, padx=4, pady=2)

    tk.Label(frame, text="Password (optional)").grid(row=4, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=password_var, show="*").grid(row=4, column=1, sticky="ew", padx=4, pady=2)

    tk.Label(frame, text="Decode after (YYYY-MM-DD HH:MM)").grid(row=5, column=0, sticky="w", padx=4, pady=2)
    tk.Entry(frame, textvariable=decode_after_var).grid(row=5, column=1, sticky="ew", padx=4, pady=2)

    def do_embed():
        cover = cover_var.get().strip()
        stego = stego_var.get().strip()
        secret = secret_var.get().strip()
        if not cover or not stego or not secret:
            messagebox.showwarning("Missing inputs", "Pick cover video, output stego path, and secret file.")
            return
        if not validate_decode_after_input(decode_after_var.get()):
            return
        password = password_var.get().strip()
        if password:
            args = ["video_encrypt_embed_file", cover, stego, secret, password]
        else:
            args = ["video_embed_file", cover, stego, secret]

        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def on_done(success):
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")
            if success:
                store_decode_after_metadata(stego, decode_after_var.get(), log_widget)
                messagebox.showinfo("Done", "Embedding finished.")
            else:
                messagebox.showerror("Failed", "Embedding failed. See log.")

        run_stego_stream(args, log_widget, progress_var, on_done)

    def do_extract():
        stego = stego_var.get().strip()
        output = output_var.get().strip()
        if not stego or not output:
            messagebox.showwarning("Missing inputs", "Pick stego video and an output file path.")
            return
        decode_after_value = resolve_decode_after_value(stego, decode_after_var.get(), log_widget)
        if not enforce_decode_after(decode_after_value):
            return
        password = password_var.get().strip()
        if password:
            args = ["video_encrypt_extract_file", stego, password, output]
        else:
            args = ["video_extract_file", stego, output]
        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def on_done(success):
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")
            if success:
                messagebox.showinfo("Done", "Extraction finished.")
            else:
                messagebox.showerror("Failed", "Extraction failed. See log.")

        run_stego_stream(args, log_widget, progress_var, on_done)

    embed_btn = tk.Button(frame, text="Embed file", command=do_embed)
    embed_btn.grid(row=6, column=1, sticky="e", padx=4, pady=4)
    extract_btn = tk.Button(frame, text="Extract file", command=do_extract)
    extract_btn.grid(row=6, column=2, sticky="w", padx=4, pady=4)
    progress_bar = ttk.Progressbar(frame, variable=progress_var, maximum=100)
    progress_bar.grid(row=7, column=0, columnspan=3, sticky="ew", padx=4, pady=2)
    tk.Label(frame, textvariable=metrics_var, anchor="w").grid(row=8, column=0, columnspan=2, sticky="ew", padx=4, pady=4)

    def run_metrics():
        cover = cover_var.get().strip()
        stego = stego_var.get().strip()
        if not cover or not stego:
            messagebox.showwarning("Missing paths", "Pick both cover and stego video for metrics.")
            return
        embed_btn.configure(state="disabled")
        extract_btn.configure(state="disabled")
        if metrics_btn:
            metrics_btn.configure(state="disabled")

        def done():
            embed_btn.configure(state="normal")
            extract_btn.configure(state="normal")
            if metrics_btn:
                metrics_btn.configure(state="normal")

        run_video_metrics_async(cover, stego, log_widget, metrics_var, progress_bar, progress_var, on_complete=done)

    metrics_btn = tk.Button(frame, text="Run metrics", command=run_metrics)
    metrics_btn.grid(row=8, column=2, sticky="e", padx=4, pady=4)

    frame._progress_bar = progress_bar  # type: ignore
    frame._progress_var = progress_var  # type: ignore
    frame._metrics_var = metrics_var    # type: ignore

    return metrics_var


def main():
    root = tk.Tk()
    root.title("IMGAE VIDEO Stego GUI")
    root.geometry("1120x860")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)

    log_frame = tk.LabelFrame(root, text="Log")
    log_frame.grid(row=1, column=0, padx=8, pady=8, sticky="nsew")
    log_frame.rowconfigure(0, weight=1)
    log_frame.columnconfigure(0, weight=1)
    log_widget = scrolledtext.ScrolledText(log_frame, state="disabled", height=12)
    log_widget.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=4, pady=4)
    tk.Button(log_frame, text="Clear log", command=lambda: clear_log(log_widget)).grid(row=1, column=1, sticky="e", padx=4, pady=4)

    notebook = ttk.Notebook(root)
    notebook.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")

    image_tab = tk.Frame(notebook)
    image_tab.columnconfigure(0, weight=1)
    build_image_section(image_tab, log_widget)
    notebook.add(image_tab, text="Image")

    video_text_tab = tk.Frame(notebook)
    video_text_tab.columnconfigure(0, weight=1)
    build_video_text_section(video_text_tab, log_widget)
    notebook.add(video_text_tab, text="Video (Text)")

    video_file_tab = tk.Frame(notebook)
    video_file_tab.columnconfigure(0, weight=1)
    build_video_file_section(video_file_tab, log_widget)
    notebook.add(video_file_tab, text="Video (File)")

    root.mainloop()


if __name__ == "__main__":
    main()
