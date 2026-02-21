/**
 * CLI: openclaw doctor
 */
import type { OpenClawConfig } from '../../types/index.js';
import { runSecurityDoctor, printDoctorResults } from '../securityDoctor.js';

export async function doctorCommand(config: OpenClawConfig): Promise<void> {
  const results = await runSecurityDoctor(config);
  printDoctorResults(results);

  const failures = results.filter(r => r.status === 'FAIL');
  if (failures.length > 0) {
    process.exit(1);
  }
}
