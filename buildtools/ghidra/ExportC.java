import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions;
import java.io.*;

public class ExportC extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        String out = "/home/james/ghidrawork2/recovered.c";
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);
        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(out)));
        int ok = 0, bad = 0;
        long lines = 0;
        FunctionIterator it = prog.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            long bytes = f.getBody().getNumAddresses();
            DecompileResults r = di.decompileFunction(f, 45, monitor);
            if (r == null || r.getDecompiledFunction() == null) { bad++; continue; }
            String c = r.getDecompiledFunction().getC();
            if (c == null || c.trim().isEmpty()) { bad++; continue; }
            w.println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() +
                      "  " + bytes + " bytes ==== */");
            w.println(c);
            w.println("");
            lines += c.split("\n").length;
            ok++;
            if (ok % 2000 == 0) println("  ... " + ok + " functions written");
        }
        w.close();
        di.dispose();
        println("EXPORT DONE: " + ok + " functions, " + bad + " failed, " +
                lines + " C lines -> " + out);
    }
}
