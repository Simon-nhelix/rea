import type { Logger } from "pino";
import { CodeReferenceService } from "../application/romhacking/CodeReferenceService.js";
import type { EvidenceWriter } from "../application/investigation/InvestigationRecordPort.js";
import { toolContract } from "../contracts/toolContracts.js";
import type { WithAdmittedAnalysis } from "./analysisAdmission.js";
import { createEvidenceToolHandler } from "./contractToolHandler.js";
import type { EvidenceMcpServer } from "./EvidenceMcpServer.js";
import { toolRegistrationOptions } from "./toolRegistrationOptions.js";

/** Bind multi-file MIPS reference search to its contract. */
export const registerCodeReferenceTools = (
  server: EvidenceMcpServer,
  logger: Logger,
  recordEvidence?: EvidenceWriter["recordEvidence"],
  withAdmittedAnalysis?: WithAdmittedAnalysis,
): void => {
  const service = new CodeReferenceService();
  const contract = toolContract("find_code_references");
  const handler = createEvidenceToolHandler(
    server,
    (input, options) => service.find(input, options),
    logger,
    recordEvidence,
    withAdmittedAnalysis,
  );
  server.registerTool(
    contract.name,
    toolRegistrationOptions(contract),
    handler(contract),
  );
};
