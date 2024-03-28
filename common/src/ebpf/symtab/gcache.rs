use std::collections::HashMap;
extern crate lru;

use lru::LruCache;
use std::fmt::Debug;
use std::hash::Hash;
use std::num::NonZeroUsize;

pub trait Resource {
    fn refresh(&mut self);
    fn cleanup(&mut self);
}

pub struct GCache<K: Hash + Eq + Clone, V: Resource> {
    options: GCacheOptions,
    round_cache: HashMap<K, Entry<V>>,
    lru_cache: LruCache<K, Entry<V>>,
    round: i32,
}

impl<K: Hash + Eq + Clone, V: Resource> GCache<K, V> {
    pub fn new(options: GCacheOptions) -> Self {
        let lru_cache_size = NonZeroUsize::try_from(options.size).unwrap();
        let lru_cache = LruCache::<K, Entry<V>>::new(lru_cache_size);
        let round_cache = HashMap::<K, Entry<V>>::new();

        Self { options, round_cache, lru_cache, round: 0 }
    }

    pub fn next_round(&mut self) {
        self.round += 1;
    }

    pub fn get(&mut self, k: K) -> V {
        if let Some(entry) = self.lru_cache.get_mut(&k) {
            if entry.round != self.round {
                entry.round = self.round;
                entry.v.refresh();
            }
            entry.v.clone()
        } else if let Some(entry) = self.round_cache.get_mut(&k) {
            if entry.round != self.round {
                entry.round = self.round;
                entry.v.refresh();
            }
            entry.v.clone()
        } else {
            V::default()
        }
    }

    pub fn cache(&mut self, k: K, v: V) {
        let mut entry = Entry { v, round: self.round };
        entry.v.refresh();
        self.lru_cache.put(k.clone(), entry.clone());
        self.round_cache.insert(k, entry);
    }

    pub fn update(&mut self, options: GCacheOptions) {
        let lru_cache_size = NonZeroUsize::try_from(options.size).unwrap();
        self.lru_cache.resize(lru_cache_size);
        self.options = options;
    }

    pub fn cleanup(&mut self) {
        let keys: Vec<K> = self.lru_cache.keys().cloned().collect();
        for key in keys {
            if let Some(entry) = self.lru_cache.get_mut(&key) {
                entry.v.cleanup();
            }
        }

        let next_round_cache = self.round_cache.iter_mut()
            .map(|(k, entry)| {
                let mut entry = entry.clone(); // Clone the entry
                entry.v.cleanup(); // Mutate the cloned entry
                (*k.clone(), entry) // Return the key-value pair for insertion into next_round_cache
            })
            .filter(|(_, entry)| entry.round >= self.round - self.options.keep_rounds)
            .collect::<HashMap<_, _>>();
        self.round_cache = next_round_cache;
    }

    pub fn lru_size(&self) -> usize {
        self.lru_cache.len()
    }

    pub fn round_size(&self) -> usize {
        self.round_cache.len()
    }

    pub fn remove(&mut self, k: K) {
        self.lru_cache.pop(&k);
        self.round_cache.remove(&k);
    }

    pub fn each(&self, f: impl Fn(K, V, i32)) {
        self.each_lru(&f);
        self.each_round(&f);
    }

    pub fn each_lru(&self, f: &impl Fn(K, V, i32)) {
        for (k, entry) in self.lru_cache.iter() {
            f(k.clone(), entry.v.clone(), entry.round);
        }
    }

    pub fn each_round(&self, f: &impl Fn(K, V, i32)) {
        for (k, entry) in &self.round_cache {
            f(k.clone(), entry.v.clone(), entry.round);
        }
    }
}

#[derive(Debug)]
pub struct Entry<V> {
    v: V,
    round: i32,
}

#[derive(Debug, Clone, Copy)]
pub struct GCacheOptions {
    size: usize,
    keep_rounds: i32,
}

impl Default for GCacheOptions {
    fn default() -> Self {
        Self { size: 0, keep_rounds: 0 }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SymbolNameResolver;

impl Resource for SymbolNameResolver {
    fn refresh(&mut self) {
        // Refresh logic here
    }

    fn cleanup(&mut self) {
        // Cleanup logic here
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