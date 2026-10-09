// Headless query against an already-analyzed project (run with -process <prog> -noanalysis).
// Args: <outfile> <mode> <target>...
//   modes: decomp  <func|addr>...   decompiled C
//          disasm  <func|addr>...   disassembly listing of the function body
//          xrefs   <func|addr|sym>  references to target (callers / data refs)
//          callees <func|addr>      functions called (recursive depth 1)
//          rename  <func|addr> <newname>   rename function (needs project opened without -readOnly)
//   A target is a function name, a symbol name, or a hex address (0x... or plain).
//@category Export
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class Query extends GhidraScript {

    List<Function> resolve(String t) {
        List<Function> out = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();
        Address a = parseAddr(t);
        if (a != null) {
            Function f = fm.getFunctionContaining(a);
            if (f != null) out.add(f);
            return out;
        }
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(t) || f.getName(true).equals(t)) out.add(f);
        }
        if (out.isEmpty()) {
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(t)) {
                Function f = fm.getFunctionAt(s.getAddress());
                if (f != null) out.add(f);
            }
        }
        return out;
    }

    Address parseAddr(String t) {
        String h = t.toLowerCase().startsWith("0x") ? t.substring(2) : t;
        if (!h.matches("[0-9a-fA-F]{4,16}")) return null;
        try { return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(h); }
        catch (Exception e) { return null; }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        PrintWriter w = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8));
        String mode = args[1];
        try {
            switch (mode) {
                case "decomp": decomp(w, Arrays.copyOfRange(args, 2, args.length)); break;
                case "disasm": disasm(w, Arrays.copyOfRange(args, 2, args.length)); break;
                case "xrefs": xrefs(w, args[2]); break;
                case "callees": callees(w, args[2]); break;
                case "rename": rename(w, args[2], args[3]); break;
                default: w.println("unknown mode " + mode);
            }
        } finally { w.close(); }
    }

    void decomp(PrintWriter w, String[] targets) {
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.toggleCCode(true);
        di.openProgram(currentProgram);
        for (String t : targets) {
            List<Function> fs = resolve(t);
            if (fs.isEmpty()) { w.println("// no function matches '" + t + "'"); continue; }
            for (Function f : fs) {
                w.println("// " + f.getName(true) + " @ " + f.getEntryPoint());
                DecompileResults r = di.decompileFunction(f, 120, TaskMonitor.DUMMY);
                if (r != null && r.decompileCompleted()) w.println(r.getDecompiledFunction().getC());
                else w.println("/* failed: " + (r != null ? r.getErrorMessage() : "") + " */");
            }
        }
        di.dispose();
    }

    void disasm(PrintWriter w, String[] targets) {
        Listing l = currentProgram.getListing();
        for (String t : targets) {
            for (Function f : resolve(t)) {
                w.println("; " + f.getName(true) + " @ " + f.getEntryPoint());
                for (Instruction i : l.getInstructions(f.getBody(), true)) {
                    StringBuilder bytes = new StringBuilder();
                    try { for (byte b : i.getBytes()) bytes.append(String.format("%02x", b)); } catch (Exception e) {}
                    String lbl = "";
                    Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(i.getAddress());
                    if (s != null && !i.getAddress().equals(f.getEntryPoint())) lbl = s.getName() + ":";
                    if (!lbl.isEmpty()) w.println(lbl);
                    w.printf("  %s  %-20s %s%n", i.getAddress(), bytes, i);
                }
            }
        }
    }

    void xrefs(PrintWriter w, String t) {
        ReferenceManager rm = currentProgram.getReferenceManager();
        FunctionManager fm = currentProgram.getFunctionManager();
        List<Address> addrs = new ArrayList<>();
        Address a = parseAddr(t);
        if (a != null) addrs.add(a);
        else {
            for (Symbol s : currentProgram.getSymbolTable().getSymbols(t)) addrs.add(s.getAddress());
            for (Function f : resolve(t)) if (!addrs.contains(f.getEntryPoint())) addrs.add(f.getEntryPoint());
        }
        for (Address target : addrs) {
            w.println("# refs to " + t + " @ " + target);
            for (Reference r : rm.getReferencesTo(target)) {
                Function f = fm.getFunctionContaining(r.getFromAddress());
                w.printf("%s\t%s\t%s%n", r.getFromAddress(), r.getReferenceType(), f != null ? f.getName(true) : "-");
            }
            // thunks pointing at an external function
            Function tf = fm.getFunctionAt(target);
            if (tf != null) for (Address th : tf.getFunctionThunkAddresses(true) != null ? tf.getFunctionThunkAddresses(true) : new Address[0]) {
                for (Reference r : rm.getReferencesTo(th)) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    w.printf("%s\t%s(via thunk %s)\t%s%n", r.getFromAddress(), r.getReferenceType(), th, f != null ? f.getName(true) : "-");
                }
            }
        }
    }

    void callees(PrintWriter w, String t) {
        for (Function f : resolve(t)) {
            w.println("# " + f.getName(true) + " calls:");
            for (Function c : f.getCalledFunctions(TaskMonitor.DUMMY))
                w.printf("%s\t%s%s%n", c.getEntryPoint(), c.getName(true), c.isExternal() || c.isThunk() ? "\t(import/thunk)" : "");
        }
    }

    void rename(PrintWriter w, String t, String newName) throws Exception {
        for (Function f : resolve(t)) {
            String old = f.getName();
            f.setName(newName, SourceType.USER_DEFINED);
            w.println("renamed " + old + " -> " + newName + " @ " + f.getEntryPoint());
        }
    }
}
