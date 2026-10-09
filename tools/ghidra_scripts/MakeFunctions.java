// Pre-analysis script: disassemble + create functions at given addresses (comma separated).
// With no addresses and a Raw Binary program, seeds the start of the first block.
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class MakeFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String list = args.length > 0 ? args[0] : "";
        if (list.isEmpty() || list.equals("-")) {
            if (!currentProgram.getExecutableFormat().contains("Raw")) return;
            list = currentProgram.getMinAddress().toString();
        }
        for (String a : list.split(",")) {
            Address addr = toAddr(a.trim().replaceFirst("^0x", ""));
            disassemble(addr);
            if (getFunctionAt(addr) == null) createFunction(addr, null);
            println("MakeFunctions: seeded " + addr);
        }
    }
}
