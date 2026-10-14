import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;

/**
 * Disable the named auto-analyzers before default auto-analysis. The first
 * argument is the strict caller-selected list ("-" for none); every name
 * must exist for this program. The optional second argument is a preset
 * list disabled only when present, so a language without one never fails.
 */
public final class ReaGhidraAnalysisOptions extends HeadlessScript {
    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1 || arguments.length > 2 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "ReaGhidraAnalysisOptions requires one comma-separated analyzer-name argument");
        }
        AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);

        List<String> names = new ArrayList<>();
        if (!arguments[0].trim().equals("-")) {
            for (String requestedName : arguments[0].split(",")) {
                monitor.checkCancelled();
                String name = requestedName.trim();
                if (analysis.getAnalyzer(name) == null || !options.containsKey(name)) {
                    throw new IllegalArgumentException("Unknown Ghidra analyzer for this program: " + name);
                }
                names.add(name);
            }
        }
        if (arguments.length == 2 && !arguments[1].isBlank()) {
            for (String requestedName : arguments[1].split(",")) {
                monitor.checkCancelled();
                String name = requestedName.trim();
                if (analysis.getAnalyzer(name) != null && options.containsKey(name)) {
                    names.add(name);
                }
            }
        }

        for (String name : names) {
            monitor.checkCancelled();
            setAnalysisOption(currentProgram, name, "false");
        }
        options = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : names) {
            monitor.checkCancelled();
            if (!"false".equals(options.get(name))) {
                throw new IllegalStateException("Ghidra analyzer remained enabled: " + name);
            }
        }
    }
}
