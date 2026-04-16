# Scale Testing Strategy

## Synthetic Load Test Suite (k6)

All load tests live in `loadtests/` and are run with [k6](https://k6.io/).

### Registration Waves

Simulate concurrent account registration to stress the OPRF-based registration flow and Postgres write path.

| Tier | Concurrent Users | Duration | Success Criteria |
|------|-----------------|----------|------------------|
| Small | 100 | 2 min | p99 < 500ms, 0 errors |
| Medium | 1,000 | 5 min | p99 < 1s, error rate < 0.1% |
| Large | 10,000 | 10 min | p99 < 2s, error rate < 0.5% |

### Sustained Messaging

Simulate realistic messaging load with pre-registered users sending encrypted messages through the NATS-backed delivery pipeline.

| Tier | Concurrent Users | Messages/sec (target) | Duration | Success Criteria |
|------|-----------------|----------------------|----------|------------------|
| Small | 1,000 | 500 | 15 min | p99 < 200ms, 0 message loss |
| Medium | 10,000 | 5,000 | 30 min | p99 < 500ms, 0 message loss |
| Large | 100,000 | 50,000 | 60 min | p99 < 1s, message loss < 0.01% |

### Contact Discovery Storms

Stress the OPRF-based private contact discovery with large contact lists.

| Tier | Concurrent Queries | Contacts per Query | Success Criteria |
|------|-------------------|-------------------|------------------|
| Standard | 1,000 | 500 | p99 < 3s, 0 errors |

### Media Upload Bursts

Concurrent encrypted media uploads to S3-compatible storage.

| Tier | Concurrent Uploads | File Size | Success Criteria |
|------|-------------------|-----------|------------------|
| Standard | 100 | 10 MB | p99 < 10s, 0 errors, all files retrievable |

### Mixed Workload

Realistic traffic distribution simulating production usage patterns.

| Operation | Distribution | Notes |
|-----------|-------------|-------|
| Messaging | 60% | Send + receive |
| Contact discovery | 20% | OPRF queries |
| Media upload/download | 10% | Mixed sizes |
| Other (registration, profile, EKF) | 10% | Background operations |

- **Duration:** 30 minutes
- **Target load:** 10,000 concurrent users
- **Success criteria:** p99 < 1s across all operation types, error rate < 0.1%

## Failure Injection (Chaos Testing)

### Tooling

Use [toxiproxy](https://github.com/Shopify/toxiproxy) for network-level fault injection or [chaos-mesh](https://chaos-mesh.org/) for Kubernetes environments.

### Scenarios

#### Postgres

| Fault | Method | Expected Behavior |
|-------|--------|-------------------|
| 500ms latency injection | toxiproxy latency toxic | Requests degrade gracefully; no timeouts below 5s. Connection pool absorbs latency. |
| Connection drop | toxiproxy reset_peer toxic | Connection pool reconnects automatically. In-flight transactions return retriable errors. No data corruption. |

#### Redis

| Fault | Method | Expected Behavior |
|-------|--------|-------------------|
| Crash and restart | `docker stop redis && sleep 10 && docker start redis` | Rate limiting and caching degrade gracefully. Core messaging continues. Automatic reconnection on restart. |
| Memory pressure | `redis-cli CONFIG SET maxmemory 1mb` | Eviction policy activates. No OOM crash. Application handles cache misses. |

#### ScyllaDB

| Fault | Method | Expected Behavior |
|-------|--------|-------------------|
| Single node failure | Stop one node in a 3-node cluster | Reads/writes continue at reduced throughput. No data loss (RF=3). Automatic recovery when node returns. |
| Network partition | toxiproxy between nodes | Quorum reads/writes may fail; application retries succeed after partition heals. No split-brain data corruption. |

#### NATS

| Fault | Method | Expected Behavior |
|-------|--------|-------------------|
| Partition | toxiproxy between NATS and application | Messages queue in JetStream. Delivery resumes after partition heals. No message loss. |
| Slow consumer | Artificial processing delay in consumer | NATS slow consumer advisory fires. Backpressure applied. No message loss. Consumer catches up after delay removed. |

#### S3

| Fault | Method | Expected Behavior |
|-------|--------|-------------------|
| Timeout | toxiproxy timeout toxic on S3 endpoint | Upload retries with exponential backoff. Client receives retriable error. No partial uploads left behind. |
| 503 responses | Mock S3 returning 503 | Retry logic activates. Upload succeeds after transient failure clears. |

## Soak Test

Sustained load over an extended period to detect resource leaks and degradation.

- **Duration:** 72 hours
- **Load:** Target capacity (sustained mixed workload at expected peak)
- **Monitoring checkpoints:**
  - Memory leaks: RSS should not grow monotonically; track with Prometheus `process_resident_memory_bytes`
  - Connection exhaustion: Postgres, Redis, ScyllaDB connection pool utilization stays below 80%
  - ScyllaDB compaction pressure: pending compaction bytes should not grow unbounded
  - Redis memory growth: `used_memory` should stabilize, not grow linearly
  - NATS slow consumer warnings: zero slow consumer advisories under steady-state load
- **Success criteria:**
  - p99 latency stable (no upward trend over 72h)
  - No OOM kills
  - No connection pool exhaustion
  - No unrecoverable errors in application logs
  - All data retrievable and consistent after test completion

## Performance Regression Gate (CI)

### Criterion Benchmarks

- Run [Criterion.rs](https://github.com/bheisler/criterion.rs) microbenchmarks on every PR via CI
- **Fail threshold:** >10% throughput regression OR >20% p99 latency increase on any benchmark
- Benchmarks cover: OPRF evaluation, EKF key derivation, message encryption/decryption, media key generation

### k6 Smoke Test

- Run a lightweight k6 smoke test on merge to `main`
- Scenario: 50 concurrent users, mixed workload, 2-minute duration
- **Fail threshold:** any error OR p95 > 500ms

## Benchmark Publication

- Results published in `docs/benchmarks/` with:
  - Hardware specifications (CPU, RAM, storage, network)
  - Software versions (Rust toolchain, database versions, OS)
  - Methodology (test scripts, configuration, warm-up period)
  - Raw data (CSV/JSON) for reproducibility
- Comparison against the paper's iOS benchmarks (Table 7) where applicable, noting that server-side and client-side measurements are not directly comparable but establish relative performance baselines
