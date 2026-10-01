import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.DecompileOptions;

public class DumpC extends GhidraScript {
    @Override
    public void run() throws Exception {
        Program prog = currentProgram;
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);
        int n = 0;
        FunctionIterator it = prog.getFunctionManager().getFunctions(true);
        while (it.hasNext() && n < 8) {
            Function f = it.next();
            if (f.getBody().getNumAddresses() < 60) continue;
            DecompileResults r = di.decompileFunction(f, 30, monitor);
            if (r == null || r.getDecompiledFunction() == null) continue;
            println("### " + f.getName() + " @ " + f.getEntryPoint() +
                    " (" + f.getBody().getNumAddresses() + " bytes)");
            println(r.getDecompiledFunction().getC());
            println("");
            n++;
        }
        di.dispose();
    }
}
