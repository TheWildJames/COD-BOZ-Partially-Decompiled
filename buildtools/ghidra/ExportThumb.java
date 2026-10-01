// ARM32 Thumb-2 payload: force Thumb context before analysis, then export all C.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.lang.Register;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import java.io.PrintWriter;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class ExportThumb extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        println("payload: " + prog.getName() + "  lang=" + prog.getLanguageID());

        MemoryBlock text = null;
        for (MemoryBlock b : prog.getMemory().getBlocks()) {
            if (b.getName().equals(".text")) text = b;
        }
        if (text == null) { println("no .text"); return; }

        Register tmode = prog.getRegister("TMode");
        if (tmode != null) {
            try {
                prog.getProgramContext().setValue(tmode, text.getStart(), text.getEnd(),
                        new java.math.BigInteger("1"));
                println("TMode=1 over " + text.getStart() + "-" + text.getEnd());
            } catch (Exception e) {
                println("TMode set failed: " + e.getMessage());
            }
        }

        String outPath = "/home/james/ghidrawork2/payload_thumb.c";
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);

        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        int ok = 0, bad = 0;
        long lines = 0;
        FunctionIterator it = prog.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal()) continue;
            DecompileResults r = di.decompileFunction(f, 45, monitor);
            if (r == null || r.getDecompiledFunction() == null) { bad++; continue; }
            String c = r.getDecompiledFunction().getC();
            if (c == null || c.trim().isEmpty()) { bad++; continue; }
            w.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() + " ==== */");
            w.println(c);
            w.println("");
            lines += c.split("\n").length;
            ok++;
        }
        w.close();
        di.dispose();
        println("PAYLOAD EXPORT: " + ok + " fns, " + bad + " failed, " +
                lines + " C lines -> " + outPath);
    }
}