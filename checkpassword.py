from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface, DecompileOptions
import os, re, time

monitor = TaskMonitor.DUMMY
listing = currentProgram.getListing()
program_name = currentProgram.getName()
timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
outdir = os.path.expanduser("~/ghidra_reports")
report_path = os.path.join(outdir, f"{program_name}_analysis_{timestamp}.md")

if not os.path.exists(outdir):
    os.makedirs(outdir)

def safe_name(s):
    return re.sub(r'[^0-9A-Za-z_]', '_', s)[:60]

def find_strings(min_len=4):
    results = []
    it = listing.getDefinedData(True)
    while it.hasNext():
        d = it.next()
        try:
            val = d.getValue()
            if isinstance(val, str) and len(val) >= min_len:
                results.append((d.getMinAddress(), val))
        except:
            pass
    return results
-*- coding: utf-8 -*-
def analyze_byte_comparisons(func):
    ins_iter = listing.getInstructions(func.getBody(), True)
    findings = []
    prev = None
    for ins in ins_iter:
        mnem = ins.getMnemonicString().upper()
        if mnem in ("MOVZX", "MOVSX", "MOVSXD", "MOV"):
            prev = ins
        elif mnem == "CMP" and prev:
            prev_txt = prev.toString()
            if "BYTE PTR" in prev_txt:
                findings.append((prev, ins))
            prev = None
    return findings

def decompile_function(func):
    iface = DecompInterface()
    opts = DecompileOptions()
    iface.setOptions(opts)
    iface.openProgram(currentProgram)
    res = iface.decompileFunction(func, 60, monitor)
    if res.decompiledFunction:
        return res.getDecompiledFunction().getC()
    return None

print("=== Starting Deep Analysis ===")

strings = find_strings()
interesting = [(addr, s) for addr, s in strings if any(x in s.lower() for x in ["password", "try again", "correct", "wrong"])]
print(f"[+] Found {len(strings)} strings, {len(interesting)} interesting")

functions = list(currentProgram.getFunctionManager().getFunctions(True))
suspicious_funcs = []
report_lines = []

report_lines.append(f"# Ghidra Binary Analysis Report: `{program_name}`")
report_lines.append(f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
report_lines.append("## 1. Interesting Strings\n")

if interesting:
    for addr, s in interesting:
        report_lines.append(f"- `{s}` @ `{addr}`")
else:
    report_lines.append("*(No obvious password-related strings found)*")

report_lines.append("\n## 2. Functions with Byte-by-Byte Comparison Patterns\n")

for func in functions:
    matches = analyze_byte_comparisons(func)
    if matches:
        suspicious_funcs.append(func)
        listing.setComment(func.getEntryPoint(), CodeUnit.PLATE_COMMENT,
                           "Byte comparison pattern detected — possible password check.")
        try:
            func.setName("check_" + safe_name(func.getName()), SourceType.ANALYSIS)
        except:
            pass
        report_lines.append(f"### Function `{func.getName()}` @ `{func.getEntryPoint()}`")
        for mov, cmp_ in matches[:5]:
            report_lines.append(f"- `{mov}` → `{cmp_}`")
        code = decompile_function(func)
        if code:
            snippet = "\n".join(code.splitlines()[:40])
            report_lines.append("\n```c\n" + snippet + "\n```\n")

if not suspicious_funcs:
    report_lines.append("*(No byte-compare patterns found)*")

report_lines.append("\n## 3. Summary\n")
report_lines.append(f"- Total strings found: **{len(strings)}**")
report_lines.append(f"- Functions with byte-compare logic: **{len(suspicious_funcs)}**")
report_lines.append("\nReport generated automatically by Ghidra Jython script.\n")

with open(report_path, "w") as f:
    f.write("\n".join(report_lines))

print("\n=== Analysis Complete ===")
print(f"[*] Report written to: {report_path}")
print(f"[*] {len(suspicious_funcs)} functions likely involved in password or input validation.")
print("Open the Markdown report in any text editor or viewer for details.")

