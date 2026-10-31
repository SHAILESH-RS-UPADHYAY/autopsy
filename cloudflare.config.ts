import { defineConfig, defineContainer, exports } from 'cf/config';
import * as entrypoint from './worker/index.ts' with { type: 'cf-worker' };

const examiner = defineContainer({
  name: 'autopsy-examiner',
  image: { dockerfile: './Dockerfile' },
  // basic is 1/4 vCPU and 1 GiB: a case holds up to 3 MB of HTML plus nine bundles and stylesheets.
  instanceType: 'basic',
  maxInstances: 1,
});

export default defineConfig({
  worker: {
    name: 'autopsy',
    compatibilityDate: '2026-10-23',
    compatibilityFlags: ['enable_ctx_exports'],
    entrypoint,
    observability: { enabled: true },
    exports: { Examiner: exports.durableObject({ storage: 'sqlite', container: examiner }) },
  },
  containers: [examiner],
});
