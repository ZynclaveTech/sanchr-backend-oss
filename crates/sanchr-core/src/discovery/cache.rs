use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use sqlx::PgPool;
use tokio::sync::{Mutex, RwLock};

use sanchr_db::postgres::contacts as pg_contacts;
use sanchr_psi::bloom::SaltedBloomFilter;
use sanchr_psi::oprf::OprfServerSecret;

pub const DISCOVERY_SNAPSHOT_TTL_SECS: u64 = 60;

#[derive(Debug)]
pub struct DiscoverySnapshot {
    pub filter_bits: Vec<u8>,
    pub num_hashes: u32,
    pub num_bits: u64,
    pub daily_salt: Vec<u8>,
    pub generated_at: i64,
    pub registered_set: Vec<Vec<u8>>,
}

struct CachedSnapshot {
    snapshot: Arc<DiscoverySnapshot>,
    built_at: Instant,
}

#[derive(Default)]
pub struct DiscoverySnapshotCache {
    current: RwLock<Option<CachedSnapshot>>,
    rebuild_lock: Mutex<()>,
}

impl DiscoverySnapshotCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn invalidate(&self) {
        *self.current.write().await = None;
    }

    pub async fn get_or_rebuild(
        &self,
        pg_pool: &PgPool,
        oprf_secret: &OprfServerSecret,
        daily_salt: Vec<u8>,
    ) -> Result<Arc<DiscoverySnapshot>, anyhow::Error> {
        if let Some(snapshot) = self.fresh_snapshot(&daily_salt).await {
            return Ok(snapshot);
        }

        let _guard = self.rebuild_lock.lock().await;
        if let Some(snapshot) = self.fresh_snapshot(&daily_salt).await {
            return Ok(snapshot);
        }

        let snapshot = Arc::new(build_snapshot(pg_pool, oprf_secret, daily_salt).await?);
        *self.current.write().await = Some(CachedSnapshot {
            snapshot: Arc::clone(&snapshot),
            built_at: Instant::now(),
        });

        Ok(snapshot)
    }

    async fn fresh_snapshot(&self, daily_salt: &[u8]) -> Option<Arc<DiscoverySnapshot>> {
        let current = self.current.read().await;
        let cached = current.as_ref()?;
        if cached.built_at.elapsed() > Duration::from_secs(DISCOVERY_SNAPSHOT_TTL_SECS) {
            return None;
        }
        if cached.snapshot.daily_salt != daily_salt {
            return None;
        }
        Some(Arc::clone(&cached.snapshot))
    }
}

async fn build_snapshot(
    pg_pool: &PgPool,
    oprf_secret: &OprfServerSecret,
    daily_salt: Vec<u8>,
) -> Result<DiscoverySnapshot, anyhow::Error> {
    let phones = pg_contacts::get_all_registered_phones(pg_pool)
        .await
        .context("get_all_registered_phones failed")?;

    let expected = phones.len().max(1);
    let mut filter = SaltedBloomFilter::new(expected, 0.01, &daily_salt);
    let mut registered_set = Vec::with_capacity(phones.len());

    for phone in &phones {
        filter.insert(phone);
        registered_set.push(oprf_secret.compute_set_element(phone).as_bytes().to_vec());
    }

    Ok(DiscoverySnapshot {
        filter_bits: filter.to_bytes().to_vec(),
        num_hashes: filter.num_hashes() as u32,
        num_bits: filter.num_bits() as u64,
        daily_salt,
        generated_at: chrono::Utc::now().timestamp(),
        registered_set,
    })
}
