import { buildReceipt, storeReceipt } from "./verification-receipt.js";
import { runVerification } from "./verification-runner.js";
import { currentApproval } from "./acceptance-approval.js";
import { VerificationUnavailable, verifierRoot } from "./verifier-home.js";

/**
 * Aciona a aceitação independente logo depois de uma execução.
 *
 * Um agente não tem como pular esta etapa: o fluxo do harness avalia assim que a
 * execução termina. Sem aprovação vigente a avaliação não acontece — e o resultado
 * fica explicitamente sem aceitação, nunca com um "pass" inventado.
 */
export interface AutoVerification {
  attempted: boolean;
  outcome?: "pass" | "fail" | "blocked";
  receiptId?: string;
  reason?: string;
}

export function verifyAfterRun(options: {
  rootDir: string;
  workId: string;
  taskId: string;
  timeoutSeconds?: number;
  verifierRootDir?: string;
}): AutoVerification {
  const approval = currentApproval(options.workId, options.taskId, options.verifierRootDir ?? verifierRoot());
  if (!approval) {
    return {
      attempted: false,
      reason:
        `sem aprovação de aceitação independente para ${options.workId}/${options.taskId}; ` +
        `a execução não produz conclusão (pwn verify approve --work ${options.workId} --task ${options.taskId} --by <nome>)`,
    };
  }
  try {
    const result = runVerification({
      rootDir: options.rootDir,
      approval,
      timeoutSeconds: options.timeoutSeconds ?? 600,
      verifierRootDir: options.verifierRootDir,
    });
    const receipt = buildReceipt({ approval, result, verifierRootDir: options.verifierRootDir });
    storeReceipt(receipt, options.rootDir, options.verifierRootDir ?? verifierRoot());
    return { attempted: true, outcome: receipt.outcome, receiptId: receipt.receipt_id };
  } catch (error) {
    if (error instanceof VerificationUnavailable) {
      return { attempted: true, outcome: "blocked", reason: error.message };
    }
    throw error;
  }
}

/** Relatório legível do resultado, usado pelos comandos de execução. */
export function reportAutoVerification(verification: AutoVerification): void {
  if (!verification.attempted) {
    console.warn(`⚠  ${verification.reason}`);
    return;
  }
  if (verification.outcome === "pass") {
    console.log(`✓ Aceitação independente: PASS (recibo ${verification.receiptId})`);
    return;
  }
  if (verification.outcome === "blocked") {
    console.error(`✗ Aceitação independente BLOQUEADA: ${verification.reason}`);
    return;
  }
  console.error(`✗ Aceitação independente: ${verification.outcome!.toUpperCase()} (recibo ${verification.receiptId})`);
}
