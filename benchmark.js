const http = require('node:http');

const baseUrl = process.env.BENCH_URL || process.argv[2] || 'http://localhost:3000';
const totalRequests = Number(process.env.BENCH_REQUESTS || 2000);
const concurrency = Number(process.env.BENCH_CONCURRENCY || 30);

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestJson(url, options = {}) {
  const res = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });
  return {
    ok: res.ok,
    status: res.status,
    body: await res.text(),
  };
}

async function runScenario(name, fn, total = totalRequests) {
  const times = [];
  let success = 0;
  let errors = 0;
  let maxLatency = 0;
  let start = Date.now();

  const workers = [];
  for (let i = 0; i < concurrency; i += 1) {
    workers.push((async () => {
      for (let j = 0; j < Math.ceil(total / concurrency); j += 1) {
        if (success + errors >= total) break;
        const t0 = performance.now();
        try {
          const result = await fn();
          const latency = performance.now() - t0;
          times.push(latency);
          maxLatency = Math.max(maxLatency, latency);
          if (result && result.ok) {
            success += 1;
          } else {
            errors += 1;
          }
        } catch (error) {
          const latency = performance.now() - t0;
          times.push(latency);
          maxLatency = Math.max(maxLatency, latency);
          errors += 1;
        }
      }
    })());
  }

  await Promise.all(workers);

  const elapsedMs = Date.now() - start;
  const sorted = [...times].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.5)] ?? 0;
  const p95 = sorted[Math.floor(sorted.length * 0.95)] ?? 0;
  const p99 = sorted[Math.floor(sorted.length * 0.99)] ?? 0;
  const avg = times.length ? times.reduce((sum, value) => sum + value, 0) / times.length : 0;

  console.log(`\n=== ${name} ===`);
  console.log({
    baseUrl,
    totalRequests: total,
    concurrency,
    elapsedMs,
    success,
    errors,
    avgMs: Number(avg.toFixed(2)),
    p50Ms: Number(p50.toFixed(2)),
    p95Ms: Number(p95.toFixed(2)),
    p99Ms: Number(p99.toFixed(2)),
    maxMs: Number(maxLatency.toFixed(2)),
    throughputRps: Number(((success + errors) / (elapsedMs / 1000)).toFixed(2)),
  });
}

async function main() {
  console.log(`Benchmarking ${baseUrl}`);
  console.log(`Requests per scenario: ${totalRequests}`);
  console.log(`Concurrency: ${concurrency}`);

  await wait(500);

  await runScenario('GET /health', async () => {
    const res = await requestJson(`${baseUrl}/health`);
    return { ok: res.status === 200 };
  });

  await runScenario('GET /index.html', async () => {
    const res = await requestJson(`${baseUrl}/index.html`);
    return { ok: res.status === 200 };
  });

  await runScenario('GET /api/courses', async () => {
    const res = await requestJson(`${baseUrl}/api/courses`);
    return { ok: res.status === 200 };
  });

  await runScenario('POST /api/auth/login (invalid body)', async () => {
    const res = await requestJson(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      body: JSON.stringify({
        identifier: 'bench@example.com',
        password: 'wrong-password',
      }),
    });
    return { ok: res.status === 401 || res.status === 200 };
  });
}

main().catch((error) => {
  console.error('Benchmark failed.', error);
  process.exit(1);
});
