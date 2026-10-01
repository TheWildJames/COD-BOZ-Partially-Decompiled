// Decompile libs3e_android.so (arm64) and export every function to one .c file.
// The engine is what crashes on launch, not the game payload, so we need its
// recovered C to work out why the mutex owner struct arrives null.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import java.io.PrintWriter;
import java.io.BufferedWriter;
import java.io.FileWriter;

public class ExportEngine extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        String outPath = "/home/james/ghidrawork2/engine_arm64.c";
        println("engine: " + prog.getName() + "  lang=" + prog.getLanguageID());

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);

        PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(outPath)));
        int ok = 0, bad = 0, ext = 0;
        long lines = 0;
        FunctionIterator it = prog.getFunctionManager().getFunctions(true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            if (f.isExternal()) { ext++; continue; }
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
        println("ENGINE EXPORT: " + ok + " fns, " + bad + " failed, " + ext +
                " external, " + lines + " C lines -> " + outPath);
    }
}
