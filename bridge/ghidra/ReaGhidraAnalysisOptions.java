import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;

/**
 * Disable the named auto-analyzers before default auto-analysis. The first
 * argument is the strict caller-selected list ("-" for none); every name
 * must exist in this Ghidra installation. The optional second argument is a
 * preset disabled only when present, so a language without one never fails.
 *
 * REA_GHIDRA_DISABLED_ANALYZERS is process-wide, but Ghidra registers only the
 * installed analyzers whose canAnalyze(program) accepts this program. A name an
 * installed analyzer provides without being registered here is not applicable
 * and is recorded instead of rejected; a strict name no installed analyzer
 * provides aborts the import. The outcome is stored as a program property that
 * the bridge reports during its handshake.
 */
public final class ReaGhidraAnalysisOptions extends HeadlessScript {
    static final String REPORT_OPTION = "REA disabled analyzers";
    private static final String SETTING = "REA_GHIDRA_DISABLED_ANALYZERS";

    @Override
    public void run() throws Exception {
        String[] arguments = getScriptArgs();
        if (arguments.length < 1 || arguments.length > 2 || arguments[0].isBlank()) {
            throw new IllegalArgumentException(
                "ReaGhidraAnalysisOptions requires one comma-separated " + SETTING + " argument");
        }

        Set<String> strictNames = new HashSet<>();
        Set<String> uniqueNames = new LinkedHashSet<>();
        if (!arguments[0].trim().equals("-")) {
            for (String requestedName : arguments[0].split(",")) {
                String name = requestedName.trim();
                strictNames.add(name);
                uniqueNames.add(name);
            }
        }
        if (arguments.length == 2 && !arguments[1].isBlank()) {
            for (String requestedName : arguments[1].split(",")) {
                uniqueNames.add(requestedName.trim());
            }
        }
        List<String> names = new ArrayList<>(uniqueNames);
        boolean[] registered = new boolean[names.size()];
        AutoAnalysisManager analysis = AutoAnalysisManager.getAnalysisManager(currentProgram);
        Map<String, String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
        Set<String> installed = null;
        for (int index = 0; index < names.size(); index++) {
            monitor.checkCancelled();
            String name = names.get(index);
            if (analysis.getAnalyzer(name) != null) {
                if (!options.containsKey(name)) {
                    throw new IllegalStateException(SETTING + " names " + name +
                        ", which Ghidra registered for this program without an enablement option");
                }
                registered[index] = true;
                continue;
            }
            if (strictNames.contains(name)) {
                if (installed == null) installed = installedAnalyzerNames();
                if (!installed.contains(name)) {
                    throw new IllegalArgumentException(SETTING + " names " + name +
                        ", which is not an analyzer in this Ghidra installation");
                }
            }
        }
        for (int index = 0; index < names.size(); index++) {
            monitor.checkCancelled();
            if (registered[index]) setAnalysisOption(currentProgram, names.get(index), "false");
        }
        options = getCurrentAnalysisOptionsAndValues(currentProgram);
        JsonArray analyzers = new JsonArray();
        for (int index = 0; index < names.size(); index++) {
            monitor.checkCancelled();
            String name = names.get(index);
            if (registered[index] && !"false".equals(options.get(name))) {
                throw new IllegalStateException(SETTING + " names " + name +
                    ", which remained enabled for this program");
            }
            JsonObject analyzer = new JsonObject();
            analyzer.addProperty("name", name);
            analyzer.addProperty("status", registered[index] ? "disabled" : "not_applicable");
            analyzers.add(analyzer);
        }
        JsonObject report = new JsonObject();
        report.addProperty("format", "rea-ghidra-disabled-analyzers-v1");
        report.add("analyzers", analyzers);
        currentProgram.getOptions(Program.PROGRAM_INFO).setString(REPORT_OPTION, report.toString());
        println("REA disabled analyzers: " + report);
    }

    /** The same analyzer universe AutoAnalysisManager filters by canAnalyze(program). */
    private static Set<String> installedAnalyzerNames() {
        Set<String> names = new HashSet<>();
        for (Analyzer analyzer : ClassSearcher.getInstances(Analyzer.class)) {
            names.add(analyzer.getName());
        }
        return names;
    }
}
