use std::collections::HashMap;
extern crate lru;

use lru::LruCache;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::ops::Deref;
use std::sync::Arc;
use crate::ebpf::symtab::symbols::PidKey;

pub trait Resource {
    fn refresh(&mut self);
    fn cleanup(&mut self);
}

#[derive(Eq, PartialEq)]
pub struct GCache<K: Eq + Hash + Clone, V: Resource> {
    options: GCacheOptions,
    round_cache: HashMap<K, Arc<Entry<V>>>,
    lru_cache: LruCache<K, Arc<Entry<V>>>,
    round: i32,
}

impl<K: Eq + Hash + Clone, V: Resource> GCache<K, V> {
    pub fn new(options: GCacheOptions) -> Self {
        let lru_cache_size = NonZeroUsize::try_from(options.size).unwrap();
        let lru_cache = LruCache::new(lru_cache_size);
        let round_cache = HashMap::new();

        Self { options, round_cache, lru_cache, round: 0 }
    }

    pub fn next_round(&mut self) {
        self.round += 1;
    }

    pub fn get(&mut self, k: &K) -> V {
        if let Some(entry) = self.lru_cache.get_mut(k) {
            if entry.round != self.round {
                entry.round = self.round;
                entry.v.refresh();
            }
            entry.v.clone()
        } else if let Some(entry) = self.round_cache.get_mut(k) {
            if entry.round != self.round {
                entry.round = self.round;
                entry.v.refresh();
            }
            entry.v.clone()
        } else {
            V::default()
        }
    }

    pub fn cache(&mut self, k: K, v: Arc<V>) {
        let mut entry = Arc::new(Entry { v, round: self.round });
        entry.v.refresh();
        self.lru_cache.put(k.clone(), entry);
        self.round_cache.insert(k, entry.clone());
    }

    pub fn update(&mut self, options: GCacheOptions) {
        let lru_cache_size = NonZeroUsize::try_from(options.size).unwrap();
        self.lru_cache.resize(lru_cache_size);
        self.options = options;
    }

    pub fn cleanup(&mut self) {
        self.lru_cache.iter_mut()
            .for_each(|(k, entry)| {
                if let Some(mut entry) = self.lru_cache.get_mut(k) {
                    entry.v.cleanup();
                }
            });

        self.round_cache.iter_mut()
            .for_each(|(k, entry)| {
                entry.v.cleanup();
            });

        self.round_cache = self.round_cache.iter_mut()
            .filter(|(_, entry)| entry.round >= self.round - self.options.keep_rounds)
            .collect();
    }

    pub fn lru_size(&self) -> usize {
        self.lru_cache.len()
    }

    pub fn round_size(&self) -> usize {
        self.round_cache.len()
    }

    pub fn remove(&mut self, k: &K) {
        self.lru_cache.pop(k);
        self.round_cache.remove(k);
    }

    pub fn each_lru(&self, f: fn(&K, &V, i32)) {
        for (k, entry) in self.lru_cache.iter() {
            f(k, &entry.v, entry.round);
        }
    }

    pub fn each_round(&self, f: fn(&K, &V, i32)) {
        for (k, entry) in &self.round_cache {
            f(k, &entry.v, entry.round);
        }
    }
}

#[derive(Debug)]
pub struct Entry<V> {
    v: Arc<V>,
    round: i32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GCacheOptions {
    pub size: usize,
    pub keep_rounds: i32,
}

impl Default for GCacheOptions {
    fn default() -> Self {
        Self { size: 0, keep_rounds: 0 }
    }
}

pub struct GCacheDebugInfo<T> {
    lru_size: usize,
    round_size: usize,
    current_round: i32,
    lru_dump: Vec<T>,
    round_dump: Vec<T>,
}

impl<T> GCacheDebugInfo<T> {
    pub fn new(lru_size: usize, round_size: usize, current_round: i32, lru_dump: Vec<T>, round_dump: Vec<T>) -> Self {
        Self { lru_size, round_size, current_round, lru_dump, round_dump }
    }
}

impl<T: Debug> Default for GCacheDebugInfo<T> {
    fn default() -> Self {
        Self { lru_size: 0, round_size: 0, current_round: 0, lru_dump: vec![], round_dump: vec![] }
    }
}

pub fn debug_info<K, V, D>(g: &GCache<K, V>, ff: fn(&K, &V, i32) -> D) -> GCacheDebugInfo<D>
    where
        K: Eq + Hash + Clone,
        V: Resource,
{
    let mut res = GCacheDebugInfo::<D> {
        lru_size: g.lru_size(),
        round_size: g.round_size(),
        current_round: g.round,
        lru_dump: Vec::with_capacity(g.lru_size()),
        round_dump: Vec::with_capacity(g.round_size()),
    };
    g.each_lru(|k: &K, v: &V, round: i32| {
        res.lru_dump.push(ff(k, v, round));
    });
    g.each_round(|k: &K, v: &V, round: i32| {
        res.round_dump.push(ff(k, v, round));
    });

    res
}
