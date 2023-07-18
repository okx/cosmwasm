use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::backend::{Backend, BackendApi, Querier, Storage};
use crate::capabilities::required_capabilities_from_module;
use crate::checksum::Checksum;
use crate::compatibility::check_wasm;
use crate::errors::{VmError, VmResult};
use crate::filesystem::mkdir_p;
use crate::instance::{Instance, InstanceOptions};
use crate::modules::{FileSystemCache, InMemoryCache, PinnedMemoryCache};
use crate::size::Size;
use crate::static_analysis::{deserialize_wasm, has_ibc_entry_points};
use crate::wasm_backend::{compile, make_runtime_store};

const STATE_DIR: &str = "state";
// Things related to the state of the blockchain.
const WASM_DIR: &str = "wasm";

const CACHE_DIR: &str = "cache";
// Cacheable things.
const MODULES_DIR: &str = "modules";

/// Statistics about the usage of a cache instance. Those values are node
/// specific and must not be used in a consensus critical context.
/// When a node is hit by a client for simulations or other queries, hits and misses
/// increase. Also a node restart will reset the values.
///
/// All values should be increment using saturated addition to ensure the node does not
/// crash in case the stats exceed the integer limit.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub hits_pinned_memory_cache: u32,
    pub hits_memory_cache: u32,
    pub hits_fs_cache: u32,
    pub misses: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct Metrics {
    pub stats: Stats,
    pub elements_pinned_memory_cache: usize,
    pub elements_memory_cache: usize,
    pub size_pinned_memory_cache: usize,
    pub size_memory_cache: usize,
}

#[derive(Clone, Debug)]
pub struct CacheOptions {
    /// The base directory of this cache.
    ///
    /// If this does not exist, it will be created. Not sure if this behaviour
    /// is desired but wasmd relies on it.
    pub base_dir: PathBuf,
    pub available_capabilities: HashSet<String>,
    pub block_milestone: HashMap<String, u64>,
    pub memory_cache_size: Size,
    /// Memory limit for instances, in bytes. Use a value that is divisible by the Wasm page size 65536,
    /// e.g. full MiBs.
    pub instance_memory_limit: Size,
}

pub struct CacheInner {
    /// The directory in which the Wasm blobs are stored in the file system.
    wasm_path: PathBuf,
    /// Instances memory limit in bytes. Use a value that is divisible by the Wasm page size 65536,
    /// e.g. full MiBs.
    instance_memory_limit: Size,
    pinned_memory_cache: PinnedMemoryCache,
    memory_cache: InMemoryCache,
    fs_cache: FileSystemCache,
    stats: Stats,
}

pub struct Cache<A: BackendApi, S: Storage, Q: Querier> {
    /// Available capabilities are immutable for the lifetime of the cache,
    /// i.e. any number of read-only references is allowed to access it concurrently.
    available_capabilities: HashSet<String>,
    inner: Mutex<CacheInner>,
    // Those two don't store data but only fix type information
    type_api: PhantomData<A>,
    type_storage: PhantomData<S>,
    type_querier: PhantomData<Q>,
    /// To prevent concurrent access to `WasmerInstance::new`
    instantiation_lock: Mutex<()>,

    block_milestone: HashMap<String, u64>,
}

#[derive(PartialEq, Eq, Debug)]
pub struct AnalysisReport {
    pub has_ibc_entry_points: bool,
    pub required_capabilities: HashSet<String>,
}

impl<A, S, Q> Cache<A, S, Q>
where
    A: BackendApi + 'static, // 'static is needed by `impl<…> Instance`
    S: Storage + 'static,    // 'static is needed by `impl<…> Instance`
    Q: Querier + 'static,    // 'static is needed by `impl<…> Instance`
{
    /// Creates a new cache that stores data in `base_dir`.
    ///
    /// # Safety
    ///
    /// This function is marked unsafe due to `FileSystemCache::new`, which implicitly
    /// assumes the disk contents are correct, and there's no way to ensure the artifacts
    /// stored in the cache haven't been corrupted or tampered with.
    pub unsafe fn new(options: CacheOptions) -> VmResult<Self> {
        let CacheOptions {
            base_dir,
            available_capabilities,
            block_milestone,
            memory_cache_size,
            instance_memory_limit,
        } = options;

        let state_path = base_dir.join(STATE_DIR);
        let cache_path = base_dir.join(CACHE_DIR);

        let wasm_path = state_path.join(WASM_DIR);

        // Ensure all the needed directories exist on disk.
        mkdir_p(&state_path).map_err(|_e| VmError::cache_err("Error creating state directory"))?;
        mkdir_p(&cache_path).map_err(|_e| VmError::cache_err("Error creating cache directory"))?;
        mkdir_p(&wasm_path).map_err(|_e| VmError::cache_err("Error creating wasm directory"))?;

        let fs_cache = FileSystemCache::new(cache_path.join(MODULES_DIR))
            .map_err(|e| VmError::cache_err(format!("Error file system cache: {}", e)))?;
        Ok(Cache {
            available_capabilities,
            block_milestone,
            inner: Mutex::new(CacheInner {
                wasm_path,
                instance_memory_limit,
                pinned_memory_cache: PinnedMemoryCache::new(),
                memory_cache: InMemoryCache::new(memory_cache_size),
                fs_cache,
                stats: Stats::default(),
            }),
            type_storage: PhantomData::<S>,
            type_api: PhantomData::<A>,
            type_querier: PhantomData::<Q>,
            instantiation_lock: Mutex::new(()),
        })
    }

    pub fn stats(&self) -> Stats {
        self.inner.lock().unwrap().stats
    }

    pub fn metrics(&self) -> Metrics {
        let cache = self.inner.lock().unwrap();
        Metrics {
            stats: cache.stats,
            elements_pinned_memory_cache: cache.pinned_memory_cache.len(),
            elements_memory_cache: cache.memory_cache.len(),
            size_pinned_memory_cache: cache.pinned_memory_cache.size(),
            size_memory_cache: cache.memory_cache.size(),
        }
    }

    pub fn save_wasm(&self, wasm: &[u8]) -> VmResult<Checksum> {
        check_wasm(wasm, &self.available_capabilities)?;
        let module = compile(wasm, None, &[])?;

        let mut cache = self.inner.lock().unwrap();
        let checksum = save_wasm_to_disk(&cache.wasm_path, wasm)?;
        cache.fs_cache.store(&checksum, &module)?;
        Ok(checksum)
    }

    /// Removes the Wasm blob for the given checksum from disk and its
    /// compiled module from the file system cache.
    ///
    /// The existence of the original code is required since the caller (wasmd)
    /// has to keep track of which entries we have here.
    pub fn remove_wasm(&self, checksum: &Checksum) -> VmResult<()> {
        let mut cache = self.inner.lock().unwrap();

        // Remove compiled moduled from disk (if it exists).
        // Here we could also delete from memory caches but this is not really
        // necessary as they are pushed out from the LRU over time or disappear
        // when the node process restarts.
        cache.fs_cache.remove(checksum)?;

        let path = &cache.wasm_path;
        remove_wasm_from_disk(path, checksum)?;
        Ok(())
    }

    /// Retrieves a Wasm blob that was previously stored via save_wasm.
    /// When the cache is instantiated with the same base dir, this finds Wasm files on disc across multiple cache instances (i.e. node restarts).
    /// This function is public to allow a checksum to Wasm lookup in the blockchain.
    ///
    /// If the given ID is not found or the content does not match the hash (=ID), an error is returned.
    pub fn load_wasm(&self, checksum: &Checksum) -> VmResult<Vec<u8>> {
        self.load_wasm_with_path(&self.inner.lock().unwrap().wasm_path, checksum)
    }

    fn load_wasm_with_path(&self, wasm_path: &Path, checksum: &Checksum) -> VmResult<Vec<u8>> {
        let code = load_wasm_from_disk(wasm_path, checksum)?;
        // verify hash matches (integrity check)
        if Checksum::generate(&code) != *checksum {
            Err(VmError::integrity_err())
        } else {
            Ok(code)
        }
    }

    /// Performs static anlyzation on this Wasm without compiling or instantiating it.
    ///
    /// Once the contract was stored via [`save_wasm`], this can be called at any point in time.
    /// It does not depend on any caching of the contract.
    pub fn analyze(&self, checksum: &Checksum) -> VmResult<AnalysisReport> {
        // Here we could use a streaming deserializer to slightly improve performance. However, this way it is DRYer.
        let wasm = self.load_wasm(checksum)?;
        let module = deserialize_wasm(&wasm)?;
        Ok(AnalysisReport {
            has_ibc_entry_points: has_ibc_entry_points(&module),
            required_capabilities: required_capabilities_from_module(&module),
        })
    }

    /// Pins a Module that was previously stored via save_wasm.
    ///
    /// The module is lookup first in the memory cache, and then in the file system cache.
    /// If not found, the code is loaded from the file system, compiled, and stored into the
    /// pinned cache.
    /// If the given ID is not found, or the content does not match the hash (=ID), an error is returned.
    pub fn pin(&self, checksum: &Checksum) -> VmResult<()> {
        let mut cache = self.inner.lock().unwrap();
        if cache.pinned_memory_cache.has(checksum) {
            return Ok(());
        }

        // Try to get module from the memory cache
        if let Some(module) = cache.memory_cache.load(checksum)? {
            cache.stats.hits_memory_cache = cache.stats.hits_memory_cache.saturating_add(1);
            return cache
                .pinned_memory_cache
                .store(checksum, module.module, module.size);
        }

        // Try to get module from file system cache
        let store = make_runtime_store(Some(cache.instance_memory_limit));
        if let Some(module) = cache.fs_cache.load(checksum, &store)? {
            cache.stats.hits_fs_cache = cache.stats.hits_fs_cache.saturating_add(1);
            let module_size = loupe::size_of_val(&module);
            return cache
                .pinned_memory_cache
                .store(checksum, module, module_size);
        }

        // Re-compile from original Wasm bytecode
        let code = self.load_wasm_with_path(&cache.wasm_path, checksum)?;
        let module = compile(&code, Some(cache.instance_memory_limit), &[])?;
        // Store into the fs cache too
        cache.fs_cache.store(checksum, &module)?;
        let module_size = loupe::size_of_val(&module);
        cache
            .pinned_memory_cache
            .store(checksum, module, module_size)
    }

    /// Unpins a Module, i.e. removes it from the pinned memory cache.
    ///
    /// Not found IDs are silently ignored, and no integrity check (checksum validation) is done
    /// on the removed value.
    pub fn unpin(&self, checksum: &Checksum) -> VmResult<()> {
        self.inner
            .lock()
            .unwrap()
            .pinned_memory_cache
            .remove(checksum)
    }

    /// Returns an Instance tied to a previously saved Wasm.
    ///
    /// It takes a module from cache or Wasm code and instantiates it.
    pub fn get_instance(
        &self,
        checksum: &Checksum,
        backend: Backend<A, S, Q>,
        options: InstanceOptions,
        block_heigh: u64,
    ) -> VmResult<Instance<A, S, Q>> {
        let module = self.get_module(checksum)?;
        let instance = Instance::from_module(
            &module,
            backend,
            options.gas_limit,
            options.print_debug,
            None,
            Some(&self.instantiation_lock),
            block_heigh,
        )?;
        Ok(instance)
    }

    /// Returns a module tied to a previously saved Wasm.
    /// Depending on availability, this is either generated from a memory cache, file system cache or Wasm code.
    /// This is part of `get_instance` but pulled out to reduce the locking time.
    fn get_module(&self, checksum: &Checksum) -> VmResult<wasmer::Module> {
        let mut cache = self.inner.lock().unwrap();
        // Try to get module from the pinned memory cache
        if let Some(module) = cache.pinned_memory_cache.load(checksum)? {
            cache.stats.hits_pinned_memory_cache =
                cache.stats.hits_pinned_memory_cache.saturating_add(1);
            return Ok(module);
        }

        // Get module from memory cache
        if let Some(module) = cache.memory_cache.load(checksum)? {
            cache.stats.hits_memory_cache = cache.stats.hits_memory_cache.saturating_add(1);
            return Ok(module.module);
        }

        // Get module from file system cache
        let store = make_runtime_store(Some(cache.instance_memory_limit));
        if let Some(module) = cache.fs_cache.load(checksum, &store)? {
            cache.stats.hits_fs_cache = cache.stats.hits_fs_cache.saturating_add(1);
            let module_size = loupe::size_of_val(&module);
            cache
                .memory_cache
                .store(checksum, module.clone(), module_size)?;
            return Ok(module);
        }

        // Re-compile module from wasm
        //
        // This is needed for chains that upgrade their node software in a way that changes the module
        // serialization format. If you do not replay all transactions, previous calls of `save_wasm`
        // stored the old module format.
        let wasm = self.load_wasm_with_path(&cache.wasm_path, checksum)?;
        cache.stats.misses = cache.stats.misses.saturating_add(1);
        let module = compile(&wasm, Some(cache.instance_memory_limit), &[])?;
        cache.fs_cache.store(checksum, &module)?;
        let module_size = loupe::size_of_val(&module);
        cache
            .memory_cache
            .store(checksum, module.clone(), module_size)?;
        Ok(module)
    }
}

unsafe impl<A, S, Q> Sync for Cache<A, S, Q>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
}

unsafe impl<A, S, Q> Send for Cache<A, S, Q>
where
    A: BackendApi + 'static,
    S: Storage + 'static,
    Q: Querier + 'static,
{
}

/// save stores the wasm code in the given directory and returns an ID for lookup.
/// It will create the directory if it doesn't exist.
/// Saving the same byte code multiple times is allowed.
fn save_wasm_to_disk(dir: impl Into<PathBuf>, wasm: &[u8]) -> VmResult<Checksum> {
    // calculate filename
    let checksum = Checksum::generate(wasm);
    let filename = checksum.to_hex();
    let filepath = dir.into().join(filename);

    // write data to file
    // Since the same filename (a collision resistent hash) cannot be generated from two different byte codes
    // (even if a malicious actor tried), it is safe to override.
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(filepath)
        .map_err(|e| VmError::cache_err(format!("Error opening Wasm file for writing: {}", e)))?;
    file.write_all(wasm)
        .map_err(|e| VmError::cache_err(format!("Error writing Wasm file: {}", e)))?;

    Ok(checksum)
}

fn load_wasm_from_disk(dir: impl Into<PathBuf>, checksum: &Checksum) -> VmResult<Vec<u8>> {
    // this requires the directory and file to exist
    let path = dir.into().join(checksum.to_hex());
    let mut file =
        File::open(path).map_err(|_e| VmError::cache_err("Error opening Wasm file for reading"))?;

    let mut wasm = Vec::<u8>::new();
    file.read_to_end(&mut wasm)
        .map_err(|_e| VmError::cache_err("Error reading Wasm file"))?;
    Ok(wasm)
}

/// Removes the Wasm blob for the given checksum from disk.
///
/// In contrast to the file system cache, the existence of the original
/// code is required. So a non-existent file leads to an error as it
/// indicates a bug.
fn remove_wasm_from_disk(dir: impl Into<PathBuf>, checksum: &Checksum) -> VmResult<()> {
    let path = dir.into().join(checksum.to_hex());

    if !path.exists() {
        return Err(VmError::cache_err("Wasm file does not exist"));
    }

    fs::remove_file(path).map_err(|_e| VmError::cache_err("Error removing Wasm file from disk"))?;

    Ok(())
}
