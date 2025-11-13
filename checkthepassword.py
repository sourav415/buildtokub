# -*- coding: utf-8 -*-
# advanced_report_generator.py
# Purpose: Deep analysis + Markdown report of possible password checking logic in ELF binaries.
# Runs inside Ghidra (Jython-based).

from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface, DecompileOptions
import os, re, time, codecs

monitor = TaskMonitor.DUMMY
listing = currentProgram.getListing()
program_name = currentProgram.getName()
timestamp = time.strftime("%Y%m%d-%H%M%S")
outdir = os.path.expanduser("~/ghidra_reports")
report_path = os.path.join(outdir, "%s_analysis_%s.md" % (program_name, timestamp))

if not os.path.exists(outdir):
    try:
        os.makedirs(outdir)
    except Exception as e:
        print("[!] Could not create output directory %s: %s" % (outdir, e))

def safe_name(s):
    # keep resulting function name safe and reasonably short
    return re.sub(r'[^0-9A-Za-z_]', '_', s)[:60]

def find_strings(min_len=4):
    """Find defined string-like data items in the program listing."""
    results = []
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            val = d.getValue()
            if isinstance(val, str) and len(val) >= min_len:
                results.append((d.getMinAddress(), val))
        except Exception:
            # ignore non-string data or odd types
            pass
    return results

def analyze_byte_comparisons(func):
    """
    Heuristic: look for MOV of byte-sized source into something followed by CMP.
    Returns list of (mov_instruction, cmp_instruction) pairs.
    """
    try:
        ins_iter = listing.getInstructions(func.getBody(), True)
    except Exception:
        # fallback: try iterating instructions by address set iterator
        return []

    findings = []
    prev = None
    for ins in ins_iter:
        try:
            mnem = ins.getMnemonicString().upper()
        except Exception:
            continue
        if mnem in ("MOVZX", "MOVSX", "MOVSXD", "MOV"):
            prev = ins
        elif mnem == "CMP" and prev:
            try:
                prev_txt = prev.toString()
                # crude check for byte-sized move
                if "BYTE PTR" in prev_txt.upper() or "BYTE" in prev_txt.upper():
                    findings.append((prev, ins))
            except Exception:
                pass
            prev = None
        else:
            # reset prev for non-matching sequences to avoid long carry-over
            prev = None
    return findings

# create and reuse decompiler interface (slightly heavier but better than recreating repeatedly)
_decomp_iface = None
def decompile_function(func, timeout=60):
    global _decomp_iface
    if _decomp_iface is None:
        _decomp_iface = DecompInterface()
        opts = DecompileOptions()
        _decomp_iface.setOptions(opts)
        _decomp_iface.openProgram(currentProgram)
    try:
        res = _decomp_iface.decompileFunction(func, timeout, monitor)
        if res and res.decompiledFunction:
            return res.getDecompiledFunction().getC()
    except Exception:
        pass
    return None

print("=== Starting Deep Analysis ===")

strings = find_strings()
# broaden keywords to catch more password-related strings
keywords = ["password", "passwd", "try again", "wrong", "incorrect", "correct", "login", "auth", "authenticate"]
interesting = [(addr, s) for addr, s in strings if any(k in s.lower() for k in keywords)]
print("[+] Found %d strings, %d interesting" % (len(strings), len(interesting)))

functions = list(currentProgram.getFunctionManager().getFunctions(True))
suspicious_funcs = []
report_lines = []

report_lines.append("# Ghidra Binary Analysis Report: `%s`" % program_name)
report_lines.append("Generated on %s\n" % time.strftime('%Y-%m-%d %H:%M:%S'))
report_lines.append("## 1. Interesting Strings\n")

if interesting:
    for addr, s in interesting:
        report_lines.append("- `%s` @ `%s`" % (s, addr))
else:
    report_lines.append("*(No obvious password-related strings found)*")

report_lines.append("\n## 2. Functions with Byte-by-Byte Comparison Patterns\n")

for func in functions:
    try:
        matches = analyze_byte_comparisons(func)
    except Exception:
        matches = []
    if matches:
        suspicious_funcs.append(func)
        # annotate the function in the listing (best-effort)
        try:
            listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT,
                               "Byte comparison pattern detected — possible password check.")
        except Exception:
            pass
        # try to give a clearer name, but don't overwrite meaningful names if SourceType prohibits
        try:
            new_name = "check_" + safe_name(func.getName())
            func.setName(new_name, SourceType.ANALYSIS)
        except Exception:
            # ignore failures to rename (e.g., already named or locked)
            pass

        report_lines.append("### Function `%s` @ `%s`" % (func.getName(), func.getEntryPoint()))
        for mov, cmp_ in matches[:10]:
            try:
                report_lines.append("- `%s` → `%s`" % (mov.toString(), cmp_.toString()))
            except Exception:
                # fall back to addresses if toString() fails
                report_lines.append("- `%s` → `%s`" % (mov.getAddress(), cmp_.getAddress()))
        # attempt decompilation (best-effort)
        code = decompile_function(func)
        if code:
            snippet = "\n".join(code.splitlines()[:80])
            report_lines.append("\n```c\n" + snippet + "\n```\n")
        else:
            report_lines.append("*(Decompilation unavailable or failed for this function)*")

if not suspicious_funcs:
    report_lines.append("*(No byte-compare patterns found)*")

report_lines.append("\n## 3. Summary\n")
report_lines.append("- Total strings found: **%d**" % len(strings))
report_lines.append("- Functions with byte-compare logic: **%d**" % len(suspicious_funcs))
report_lines.append("\nReport generated automatically by Ghidra Jython script.\n")

# Write out the report using codecs to ensure UTF-8 works in environments without 'encoding' kw arg.
try:
    with codecs.open(report_path, "w", "utf-8") as f:
        f.write("\n".join(report_lines))
    print("\n=== Analysis Complete ===")
    print("[*] Report written to: %s" % report_path)
    print("[*] %d functions likely involved in password or input validation." % len(suspicious_funcs))
    print("Open the Markdown report in any text editor or viewer for details.")
except Exception as e:
    print("[!] Failed to write report to %s: %s" % (report_path, e))
    # fallback: attempt a simpler write without codecs
    try:
        with open(report_path, "w") as f:
            f.write("\n".join(report_lines))
        print("[*] Report written (fallback) to: %s" % report_path)
    except Exception as e2:
        print("[!] Final failure writing report: %s" % e2)
