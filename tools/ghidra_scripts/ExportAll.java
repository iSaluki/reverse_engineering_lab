// Headless post-script: dump an analyzed program to grep-friendly text files.
// Args: <outdir> [decomp=1|0] [timeoutSecs=60] [threads=N]
//   outdir/summary.txt      program metadata + counts
//   outdir/functions.tsv    addr, name, size, #callers, #callees, flags, signature
//   outdir/imports.tsv      library, symbol, address
//   outdir/exports.tsv      symbol, address
//   outdir/strings.tsv      addr, length, functions referencing it, value (escaped)
//   outdir/decomp/<addr>_<name>.c   one decompiled function per file, with call-graph header
//@category Export
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class ExportAll extends GhidraScript {

    static String esc(String s) {
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\x%02x", (int) c));
            else b.append(c);
        }
        return b.toString();
    }

    static String safe(String s) {
        String r = s.replaceAll("[^A-Za-z0-9_.@$-]", "_");
        return r.length() > 80 ? r.substring(0, 80) : r;
    }

    PrintWriter open(File dir, String name) throws IOException {
        return new PrintWriter(new BufferedWriter(new OutputStreamWriter(
            new FileOutputStream(new File(dir, name)), StandardCharsets.UTF_8)));
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) { printerr("usage: ExportAll.java <outdir> [decomp] [timeout] [threads]"); return; }
        File out = new File(args[0]);
        boolean doDecomp = args.length < 2 || !args[1].equals("0");
        int timeout = args.length > 2 ? Integer.parseInt(args[2]) : 60;
        int threads = args.length > 3 ? Integer.parseInt(args[3]) : Runtime.getRuntime().availableProcessors();
        out.mkdirs();
        Program p = currentProgram;
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        SymbolTable st = p.getSymbolTable();
        ReferenceManager rm = p.getReferenceManager();

        // ---- stripped ELF: main is the function whose address entry() passes to __libc_start_main
        String mainNote = "";
        if (getGlobalFunctions("main").isEmpty()) {
            for (Function e : getGlobalFunctions("entry")) {
                boolean callsLibcStart = false;
                for (Function c : e.getCalledFunctions(TaskMonitor.DUMMY))
                    if (c.getName().contains("libc_start_main")) callsLibcStart = true;
                if (!callsLibcStart) continue;
                for (Address a : e.getBody().getAddresses(true)) {
                    for (Reference r : rm.getReferencesFrom(a)) {
                        Function t = fm.getFunctionAt(r.getToAddress());
                        if (t == null && !r.getReferenceType().isCall() && listing.getInstructionAt(r.getToAddress()) != null) {
                            t = createFunction(r.getToAddress(), null);
                        }
                        if (t != null && !t.isThunk() && !t.isExternal() && !r.getReferenceType().isCall()
                                && t.getSymbol().getSource() == SourceType.DEFAULT && mainNote.isEmpty()) {
                            mainNote = "renamed " + t.getName() + " -> main (arg of __libc_start_main)";
                            t.setName("main", SourceType.ANALYSIS);
                        }
                    }
                }
            }
        }

        // ---- functions.tsv
        List<Function> internal = new ArrayList<>();
        int nThunk = 0, nExt = 0;
        try (PrintWriter w = open(out, "functions.tsv")) {
            w.println("addr\tname\tsize\tcallers\tcallees\tflags\tsignature");
            for (Function f : fm.getFunctions(true)) {
                String flags = "";
                if (f.isThunk()) { flags += "thunk,"; nThunk++; }
                if (f.isExternal()) flags += "external,";
                if (f.getSymbol().getSource() == SourceType.DEFAULT) flags += "autoname,";
                int callers = f.getCallingFunctions(TaskMonitor.DUMMY).size();
                int callees = f.getCalledFunctions(TaskMonitor.DUMMY).size();
                w.printf("%s\t%s\t%d\t%d\t%d\t%s\t%s%n", f.getEntryPoint(), f.getName(true),
                    f.getBody().getNumAddresses(), callers, callees, flags, esc(f.getPrototypeString(false, false)));
                if (!f.isThunk() && !f.isExternal()) internal.add(f);
            }
            for (Function f : fm.getExternalFunctions()) nExt++;
        }

        // ---- imports / exports
        try (PrintWriter w = open(out, "imports.tsv")) {
            w.println("library\tsymbol\taddr");
            for (Symbol s : st.getExternalSymbols()) {
                ExternalLocation loc = p.getExternalManager().getExternalLocation(s);
                String lib = loc != null ? loc.getLibraryName() : "?";
                w.printf("%s\t%s\t%s%n", lib, s.getName(), loc != null && loc.getAddress() != null ? loc.getAddress() : "");
            }
        }
        int nExports = 0;
        try (PrintWriter w = open(out, "exports.tsv")) {
            w.println("symbol\taddr");
            for (Address a : st.getExternalEntryPointIterator()) {
                Symbol s = st.getPrimarySymbol(a);
                w.printf("%s\t%s%n", s != null ? s.getName(true) : "?", a);
                nExports++;
            }
        }

        // ---- strings.tsv (with referencing functions)
        int nStr = 0;
        try (PrintWriter w = open(out, "strings.tsv")) {
            w.println("addr\tlen\treferenced_by\tvalue");
            for (Data d : listing.getDefinedData(true)) {
                if (monitor.isCancelled()) break;
                if (!StringDataInstance.isString(d)) continue;
                Object v = d.getValue();
                if (v == null) continue;
                String s = v.toString();
                if (s.length() < 3) continue;
                Set<String> refs = new LinkedHashSet<>();
                for (Reference r : rm.getReferencesTo(d.getAddress())) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    refs.add(f != null ? f.getName() : r.getFromAddress().toString());
                    if (refs.size() >= 8) break;
                }
                w.printf("%s\t%d\t%s\t%s%n", d.getAddress(), s.length(), String.join(",", refs), esc(s));
                nStr++;
            }
        }

        // ---- summary
        try (PrintWriter w = open(out, "summary.txt")) {
            w.println("program:   " + p.getName());
            w.println("path:      " + p.getExecutablePath());
            w.println("format:    " + p.getExecutableFormat());
            w.println("language:  " + p.getLanguageID() + "  compiler: " + p.getCompilerSpec().getCompilerSpecID());
            w.println("imagebase: " + p.getImageBase());
            w.println("md5:       " + p.getExecutableMD5());
            w.println("functions: " + fm.getFunctionCount() + " (internal non-thunk " + internal.size() + ", thunks " + nThunk + ", external " + nExt + ")");
            w.println("exports:   " + nExports + "   strings: " + nStr);
            Function entry = null;
            for (Address a : st.getExternalEntryPointIterator()) {
                Function f = fm.getFunctionAt(a);
                if (f != null && (f.getName().equals("entry") || f.getName().equals("_start") || f.getName().equals("main"))) entry = f;
            }
            Function mainF = null;
            for (Function f : fm.getFunctions(true)) {
                String n = f.getName();
                if (n.equals("main") || n.equals("WinMain") || n.equals("wWinMain") || n.equals("main.main") || n.equals("DllMain")) { mainF = f; break; }
            }
            if (entry != null) w.println("entry:     " + entry.getName() + " @ " + entry.getEntryPoint());
            if (mainF != null) w.println("main:      " + mainF.getName() + " @ " + mainF.getEntryPoint() + (mainNote.isEmpty() ? "" : "   [" + mainNote + "]"));
            w.println("memory blocks:");
            for (String b : blocks(p)) w.println("  " + b);
        }

        if (!doDecomp) { println("ExportAll: done (no decompilation) -> " + out); return; }

        // ---- parallel decompilation, one DecompInterface per worker
        File dd = new File(out, "decomp");
        dd.mkdirs();
        ConcurrentLinkedQueue<Function> q = new ConcurrentLinkedQueue<>(internal);
        AtomicInteger done = new AtomicInteger(), failed = new AtomicInteger();
        int total = internal.size();
        ExecutorService ex = Executors.newFixedThreadPool(Math.max(1, threads));
        List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < Math.max(1, threads); t++) {
            fs.add(ex.submit(() -> {
                DecompInterface di = new DecompInterface();
                DecompileOptions opts = new DecompileOptions();
                di.setOptions(opts);
                di.toggleCCode(true);
                di.toggleSyntaxTree(false);
                di.setSimplificationStyle("decompile");
                di.openProgram(p);
                Function f;
                while ((f = q.poll()) != null) {
                    if (monitor.isCancelled()) break;
                    StringBuilder hdr = new StringBuilder();
                    hdr.append("// ").append(f.getName(true)).append(" @ ").append(f.getEntryPoint()).append("\n");
                    hdr.append("// called by: ").append(names(f.getCallingFunctions(TaskMonitor.DUMMY))).append("\n");
                    hdr.append("// calls:     ").append(names(f.getCalledFunctions(TaskMonitor.DUMMY))).append("\n");
                    String body;
                    try {
                        DecompileResults r = di.decompileFunction(f, timeout, TaskMonitor.DUMMY);
                        if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                            body = r.getDecompiledFunction().getC();
                        } else {
                            body = "/* decompilation failed: " + (r != null ? r.getErrorMessage() : "null") + " */\n";
                            failed.incrementAndGet();
                        }
                    } catch (Exception e) {
                        body = "/* decompilation exception: " + e + " */\n";
                        failed.incrementAndGet();
                    }
                    File of = new File(dd, f.getEntryPoint().toString().replace(':', '_') + "_" + safe(f.getName()) + ".c");
                    try (Writer w = new OutputStreamWriter(new FileOutputStream(of), StandardCharsets.UTF_8)) {
                        w.write(hdr.toString());
                        w.write(body);
                    } catch (IOException e) { failed.incrementAndGet(); }
                    int n = done.incrementAndGet();
                    if (n % 500 == 0) println("ExportAll: decompiled " + n + "/" + total);
                }
                di.dispose();
            }));
        }
        for (Future<?> f : fs) f.get();
        ex.shutdown();
        try (PrintWriter w = new PrintWriter(new FileWriter(new File(out, "summary.txt"), true))) {
            w.println("decompiled: " + done.get() + " functions (" + failed.get() + " failed) -> decomp/");
        }
        println("ExportAll: done -> " + out);
    }

    static String names(Set<Function> s) {
        List<String> l = new ArrayList<>();
        for (Function f : s) l.add(f.getName());
        Collections.sort(l);
        if (l.size() > 25) return String.join(", ", l.subList(0, 25)) + ", ... (" + l.size() + " total)";
        return String.join(", ", l);
    }

    static List<String> blocks(Program p) {
        List<String> l = new ArrayList<>();
        for (ghidra.program.model.mem.MemoryBlock b : p.getMemory().getBlocks()) {
            if (!b.isLoaded()) continue;
            if (l.size() >= 40) { l.add("... (more blocks omitted)"); break; }
            l.add(String.format("%-20s %s-%s %s%s%s%s", b.getName(), b.getStart(), b.getEnd(),
                b.isRead() ? "r" : "-", b.isWrite() ? "w" : "-", b.isExecute() ? "x" : "-",
                b.isInitialized() ? "" : " (uninit)"));
        }
        return l;
    }
}
