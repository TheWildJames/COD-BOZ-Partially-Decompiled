import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.lang.Register;
import java.util.*;

public class RecoverElf extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        println("=== " + prog.getName() + " ===");
        println("language: " + prog.getLanguageID());

        // Work inside .text only.
        MemoryBlock text = null;
        for (MemoryBlock b : prog.getMemory().getBlocks()) {
            println("  block " + b.getName() + "  " + b.getStart() + "-" + b.getEnd() +
                    "  size=" + b.getSize() + "  init=" + b.isInitialized() + "  exec=" + b.isExecute());
            if (b.getName().equals(".text")) text = b;
        }
        if (text == null) { println("no .text block"); return; }
        Address start = text.getStart();
        Address end = text.getEnd();
        println("text: " + start + " - " + end);

        // Binariser emits Thumb-2: force TMode=1 over the code block.
        Register tmode = prog.getRegister("TMode");
        if (tmode != null) {
            try {
                prog.getProgramContext().setValue(tmode, start, end, new java.math.BigInteger("1"));
                println("TMode=1 (Thumb) over " + start + "-" + end);
            } catch (Exception e) {
                println("TMode set failed: " + e.getMessage());
            }
        }

        Listing lst = prog.getListing();
        FunctionManager fm = prog.getFunctionManager();
        println("pre-run funcs: " + fm.getFunctionCount());

        InstructionIterator ii = lst.getInstructions(start, true);
        int n0 = 0; while (ii.hasNext()) { ii.next(); n0++; }
        println("pre-run insns: " + n0);

        // Decompile whatever analysis found.
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.toggleCCode(true);
        di.toggleSyntaxTree(true);
        di.openProgram(prog);

        int ok=0, fail=0, empty=0, ext=0;
        long totalLines=0, totalBytes=0;
        List<String> samples = new ArrayList<>();
        int sampled = 0;

        FunctionIterator f2 = fm.getFunctions(true);
        while (f2.hasNext() && !monitor.isCancelled()) {
            Function f = f2.next();
            if (f.isExternal()) { ext++; continue; }
            if (f.getBody().getNumAddresses() == 0) { fail++; continue; }
            long bytes = f.getBody().getNumAddresses();
            DecompileResults res = di.decompileFunction(f, 30, monitor);
            if (res == null || !res.decompileCompleted() || res.getDecompiledFunction() == null) {
                fail++; continue;
            }
            String c = res.getDecompiledFunction().getC();
            if (c == null || c.trim().isEmpty()) { empty++; continue; }
            ok++;
            totalLines += c.split("\n").length;
            totalBytes += bytes;
            if (sampled < 5 && bytes > 80) {
                sampled++;
                String h = c.length() > 1500 ? c.substring(0,1500) : c;
                samples.add("--- " + f.getName() + " @ " + f.getEntryPoint() + " (" + bytes + " bytes)\n" + h);
            }
        }
        di.dispose();

        int nFunc = fm.getFunctionCount();
        InstructionIterator i3 = lst.getInstructions(start, true);
        int nIns = 0; while (i3.hasNext()) { i3.next(); nIns++; }

        println("");
        println("=== RESULT ===");
        println("  .text bytes    : " + text.getSize());
        println("  instructions   : " + nIns);
        println("  functions      : " + nFunc);
        println("  external syms  : " + ext);
        println("");
        println("=== DECOMPILE TALLY ===");
        println("  decompiled OK  : " + ok);
        println("  empty          : " + empty);
        println("  failed         : " + fail);
        if (ok > 0) {
            println("  avg C lines/fn : " + (totalLines / ok));
            println("  avg bytes/fn   : " + (totalBytes / ok));
        }
        println("");
        for (String s : samples) println(s);
    }
}
