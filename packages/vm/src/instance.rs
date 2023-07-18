use std::collections::{HashMap, HashSet};
use std::ptr::NonNull;
use std::sync::Mutex;

use wasmer::{Exports, Function, ImportObject, Instance as WasmerInstance, Module, Val};

use crate::backend::{Backend, BackendApi, Querier, Storage};
use crate::capabilities::required_capabilities_from_module;
use crate::conversion::{ref_to_u32, to_u32};
use crate::environment::Environment;
use crate::errors::{CommunicationError, VmError, VmResult};
use crate::imports::{
    do_abort, do_addr_canonicalize, do_addr_humanize, do_addr_validate, do_db_read, do_db_remove,
    do_db_write, do_debug, do_ed25519_batch_verify, do_ed25519_verify, do_query_chain,
    do_secp256k1_recover_pubkey, do_secp256k1_verify,
};
#[cfg(feature = "iterator")]
use crate::imports::{do_db_next, do_db_scan};
use crate::memory::{read_region, write_region};
use crate::size::Size;
use crate::wasm_backend::compile;
use backtrace::Backtrace;

#[derive(Copy, Clone, Debug)]
pub struct GasReport {
    /// The original limit the instance was created with
    pub limit: u64,
    /// The remaining gas that can be spend
    pub remaining: u64,
    /// The amount of gas that was spend and metered externally in operations triggered by this instance
    pub used_externally: u64,
    /// The amount of gas that was spend and metered internally (i.e. by executing Wasm and calling
    /// API methods which are not metered externally)
    pub used_internally: u64,
}

#[derive(Copy, Clone, Debug)]
pub struct InstanceOptions {
    /// Gas limit measured in [CosmWasm gas](https://github.com/CosmWasm/cosmwasm/blob/main/docs/GAS.md).
    pub gas_limit: u64,
    pub print_debug: bool,
}

pub struct Instance<A: BackendApi, S: Storage, Q: Querier> {
    /// We put this instance in a box to maintain a constant memory address for the entire
    /// lifetime of the instance in the cache. This is needed e.g. when linking the wasmer
    /// instance to a context. See also https://github.com/CosmWasm/cosmwasm/pull/245.
    ///
    /// This instance should only be accessed via the Environment, which provides safe access.
    _inner: Box<WasmerInstance>,
    env: Environment<A, S, Q>,
}

impl<A, S, Q> Instance<A, S, Q>
where
    A: BackendApi + 'static, // 'static is needed here to allow copying API instances into closures
    S: Storage + 'static, // 'static is needed here to allow using this in an Environment that is cloned into closures
    Q: Querier + 'static, // 'static is needed here to allow using this in an Environment that is cloned into closures
{
    /// This is the only Instance constructor that can be called from outside of cosmwasm-vm,
    /// e.g. in test code that needs a customized variant of cosmwasm_vm::testing::mock_instance*.
    pub fn from_code(
        code: &[u8],
        backend: Backend<A, S, Q>,
        options: InstanceOptions,
        memory_limit: Option<Size>,
        block_heigh: u64,
        block_milestone: HashMap<String, u64>,
    ) -> VmResult<Self> {
        let module = compile(code, memory_limit, &[])?;
        Instance::from_module(
            &module,
            backend,
            options.gas_limit,
            options.print_debug,
            None,
            None,
            block_heigh,
            block_milestone,
        )
    }

    pub fn higher_than_v2(block_milestone: HashMap<String, u64>, block_heigh: u64) -> bool {
        // println!(
        //     "block_milestone:{},block_heigh{}",
        //     block_milestone.len(),
        //     block_heigh
        // );
        if let Some(value) = block_milestone.get("v2") {
            if block_heigh >= *value {
                println!("higher_than_v2:{},{}", block_heigh, value);
                return true;
            }
        }
        return false;
    }

    pub(crate) fn from_module(
        module: &Module,
        backend: Backend<A, S, Q>,
        gas_limit: u64,
        print_debug: bool,
        extra_imports: Option<HashMap<&str, Exports>>,
        instantiation_lock: Option<&Mutex<()>>,
        block_heigh: u64,
        block_milestone: HashMap<String, u64>,
    ) -> VmResult<Self> {
        let store = module.store();

        let env = Environment::new(
            backend.api,
            gas_limit,
            print_debug,
            block_heigh,
            block_milestone.clone(),
        );

        let mut import_obj = ImportObject::new();
        let mut env_imports = Exports::new();

        // Reads the database entry at the given key into the the value.
        // Returns 0 if key does not exist and pointer to result region otherwise.
        // Ownership of the key pointer is not transferred to the host.
        // Ownership of the value pointer is transferred to the contract.
        env_imports.insert(
            "db_read",
            Function::new_native_with_env(store, env.clone(), do_db_read),
        );

        // Writes the given value into the database entry at the given key.
        // Ownership of both input and output pointer is not transferred to the host.
        env_imports.insert(
            "db_write",
            Function::new_native_with_env(store, env.clone(), do_db_write),
        );

        if Self::higher_than_v2(block_milestone, block_heigh) {
            env_imports.insert(
                "db_write_new",
                Function::new_native_with_env(store, env.clone(), do_db_write),
            );
        }

        // Removes the value at the given key. Different than writing &[] as future
        // scans will not find this key.
        // At the moment it is not possible to differentiate between a key that existed before and one that did not exist (https://github.com/CosmWasm/cosmwasm/issues/290).
        // Ownership of both key pointer is not transferred to the host.
        env_imports.insert(
            "db_remove",
            Function::new_native_with_env(store, env.clone(), do_db_remove),
        );

        // Reads human address from source_ptr and checks if it is valid.
        // Returns 0 on if the input is valid. Returns a non-zero memory location to a Region containing an UTF-8 encoded error string for invalid inputs.
        // Ownership of the input pointer is not transferred to the host.
        env_imports.insert(
            "addr_validate",
            Function::new_native_with_env(store, env.clone(), do_addr_validate),
        );

        // Reads human address from source_ptr and writes canonicalized representation to destination_ptr.
        // A prepared and sufficiently large memory Region is expected at destination_ptr that points to pre-allocated memory.
        // Returns 0 on success. Returns a non-zero memory location to a Region containing an UTF-8 encoded error string for invalid inputs.
        // Ownership of both input and output pointer is not transferred to the host.
        env_imports.insert(
            "addr_canonicalize",
            Function::new_native_with_env(store, env.clone(), do_addr_canonicalize),
        );

        // Reads canonical address from source_ptr and writes humanized representation to destination_ptr.
        // A prepared and sufficiently large memory Region is expected at destination_ptr that points to pre-allocated memory.
        // Returns 0 on success. Returns a non-zero memory location to a Region containing an UTF-8 encoded error string for invalid inputs.
        // Ownership of both input and output pointer is not transferred to the host.
        env_imports.insert(
            "addr_humanize",
            Function::new_native_with_env(store, env.clone(), do_addr_humanize),
        );

        // Verifies message hashes against a signature with a public key, using the secp256k1 ECDSA parametrization.
        // Returns 0 on verification success, 1 on verification failure, and values greater than 1 in case of error.
        // Ownership of input pointers is not transferred to the host.
        env_imports.insert(
            "secp256k1_verify",
            Function::new_native_with_env(store, env.clone(), do_secp256k1_verify),
        );

        env_imports.insert(
            "secp256k1_recover_pubkey",
            Function::new_native_with_env(store, env.clone(), do_secp256k1_recover_pubkey),
        );

        // Verifies a message against a signature with a public key, using the ed25519 EdDSA scheme.
        // Returns 0 on verification success, 1 on verification failure, and values greater than 1 in case of error.
        // Ownership of input pointers is not transferred to the host.
        env_imports.insert(
            "ed25519_verify",
            Function::new_native_with_env(store, env.clone(), do_ed25519_verify),
        );

        // Verifies a batch of messages against a batch of signatures with a batch of public keys,
        // using the ed25519 EdDSA scheme.
        // Returns 0 on verification success (all batches verify correctly), 1 on verification failure, and values
        // greater than 1 in case of error.
        // Ownership of input pointers is not transferred to the host.
        env_imports.insert(
            "ed25519_batch_verify",
            Function::new_native_with_env(store, env.clone(), do_ed25519_batch_verify),
        );

        // Allows the contract to emit debug logs that the host can either process or ignore.
        // This is never written to chain.
        // Takes a pointer argument of a memory region that must contain an UTF-8 encoded string.
        // Ownership of both input and output pointer is not transferred to the host.
        env_imports.insert(
            "debug",
            Function::new_native_with_env(store, env.clone(), do_debug),
        );

        // Aborts the contract execution with an error message provided by the contract.
        // Takes a pointer argument of a memory region that must contain an UTF-8 encoded string.
        // Ownership of both input and output pointer is not transferred to the host.
        env_imports.insert(
            "abort",
            Function::new_native_with_env(store, env.clone(), do_abort),
        );

        env_imports.insert(
            "query_chain",
            Function::new_native_with_env(store, env.clone(), do_query_chain),
        );

        // Creates an iterator that will go from start to end.
        // If start_ptr == 0, the start is unbounded.
        // If end_ptr == 0, the end is unbounded.
        // Order is defined in cosmwasm_std::Order and may be 1 (ascending) or 2 (descending). All other values result in an error.
        // Ownership of both start and end pointer is not transferred to the host.
        // Returns an iterator ID.
        #[cfg(feature = "iterator")]
        env_imports.insert(
            "db_scan",
            Function::new_native_with_env(store, env.clone(), do_db_scan),
        );

        // Get next element of iterator with ID `iterator_id`.
        // Creates a region containing both key and value and returns its address.
        // Ownership of the result region is transferred to the contract.
        // The KV region uses the format value || key || keylen, where keylen is a fixed size big endian u32 value.
        // An empty key (i.e. KV region ends with \0\0\0\0) means no more element, no matter what the value is.
        #[cfg(feature = "iterator")]
        env_imports.insert(
            "db_next",
            Function::new_native_with_env(store, env.clone(), do_db_next),
        );

        import_obj.register("env", env_imports);

        if let Some(extra_imports) = extra_imports {
            for (namespace, exports_obj) in extra_imports {
                import_obj.register(namespace, exports_obj);
            }
        }

        let wasmer_instance = Box::from(
            {
                let _lock = instantiation_lock.map(|l| l.lock().unwrap());
                WasmerInstance::new(module, &import_obj)
            }
            .map_err(|original| {
                VmError::instantiation_err(format!("Error instantiating module: {original}"))
            })?,
        );

        let instance_ptr = NonNull::from(wasmer_instance.as_ref());
        env.set_wasmer_instance(Some(instance_ptr));
        println!("--cosmwasm--from_module--{}", gas_limit);
        env.set_gas_left(gas_limit);
        env.move_in(backend.storage, backend.querier);
        let gas_left = env.get_gas_left();
        println!("--cosmwasm--from_module--end gas left--{}", gas_left);
        let instance = Instance {
            _inner: wasmer_instance,
            env,
        };
        let backtrace = Backtrace::new();
        println!("{:?}", backtrace);
        Ok(instance)
    }

    pub fn api(&self) -> &A {
        &self.env.api
    }

    /// Decomposes this instance into its components.
    /// External dependencies are returned for reuse, the rest is dropped.
    pub fn recycle(self) -> Option<Backend<A, S, Q>> {
        if let (Some(storage), Some(querier)) = self.env.move_out() {
            let api = self.env.api;
            Some(Backend {
                api,
                storage,
                querier,
            })
        } else {
            None
        }
    }

    /// Returns the features required by this contract.
    ///
    /// This is not needed for production because we can do static analysis
    /// on the Wasm file before instatiation to obtain this information. It's
    /// only kept because it can be handy for integration testing.
    pub fn required_capabilities(&self) -> HashSet<String> {
        required_capabilities_from_module(self._inner.module())
    }

    /// Returns the size of the default memory in pages.
    /// This provides a rough idea of the peak memory consumption. Note that
    /// Wasm memory always grows in 64 KiB steps (pages) and can never shrink
    /// (https://github.com/WebAssembly/design/issues/1300#issuecomment-573867836).
    pub fn memory_pages(&self) -> usize {
        self.env.memory().size().0 as _
    }

    /// Returns the currently remaining gas.
    pub fn get_gas_left(&self) -> u64 {
        self.env.get_gas_left()
    }

    /// Creates and returns a gas report.
    /// This is a snapshot and multiple reports can be created during the lifetime of
    /// an instance.
    pub fn create_gas_report(&self) -> GasReport {
        let state = self.env.with_gas_state(|gas_state| gas_state.clone());
        let gas_left = self.env.get_gas_left();
        GasReport {
            limit: state.gas_limit,
            remaining: gas_left,
            used_externally: state.externally_used_gas,
            // If externally_used_gas exceeds the gas limit, this will return 0.
            // no matter how much gas was used internally. But then we error with out of gas
            // anyways, and it does not matter much anymore where gas was spend.
            used_internally: state
                .gas_limit
                .saturating_sub(state.externally_used_gas)
                .saturating_sub(gas_left),
        }
    }

    /// Sets the readonly storage flag on this instance. Since one instance can be used
    /// for multiple calls in integration tests, this should be set to the desired value
    /// right before every call.
    pub fn set_storage_readonly(&mut self, new_value: bool) {
        self.env.set_storage_readonly(new_value);
    }

    pub fn with_storage<F: FnOnce(&mut S) -> VmResult<T>, T>(&mut self, func: F) -> VmResult<T> {
        self.env.with_storage_from_context::<F, T>(func)
    }

    pub fn with_querier<F: FnOnce(&mut Q) -> VmResult<T>, T>(&mut self, func: F) -> VmResult<T> {
        self.env.with_querier_from_context::<F, T>(func)
    }

    /// Requests memory allocation by the instance and returns a pointer
    /// in the Wasm address space to the created Region object.
    pub(crate) fn allocate(&mut self, size: usize) -> VmResult<u32> {
        let ret = self.call_function1("allocate", &[to_u32(size)?.into()])?;
        let ptr = ref_to_u32(&ret)?;
        if ptr == 0 {
            return Err(CommunicationError::zero_address().into());
        }
        Ok(ptr)
    }

    // deallocate frees memory in the instance and that was either previously
    // allocated by us, or a pointer from a return value after we copy it into rust.
    // we need to clean up the wasm-side buffers to avoid memory leaks
    pub(crate) fn deallocate(&mut self, ptr: u32) -> VmResult<()> {
        self.call_function0("deallocate", &[ptr.into()])?;
        Ok(())
    }

    /// Copies all data described by the Region at the given pointer from Wasm to the caller.
    pub(crate) fn read_memory(&self, region_ptr: u32, max_length: usize) -> VmResult<Vec<u8>> {
        read_region(&self.env.memory(), region_ptr, max_length)
    }

    /// Copies data to the memory region that was created before using allocate.
    pub(crate) fn write_memory(&mut self, region_ptr: u32, data: &[u8]) -> VmResult<()> {
        write_region(&self.env.memory(), region_ptr, data)?;
        Ok(())
    }

    /// Calls a function exported by the instance.
    /// The function is expected to return no value. Otherwise this calls errors.
    pub(crate) fn call_function0(&self, name: &str, args: &[Val]) -> VmResult<()> {
        self.env.call_function0(name, args)
    }

    /// Calls a function exported by the instance.
    /// The function is expected to return one value. Otherwise this calls errors.
    pub(crate) fn call_function1(&self, name: &str, args: &[Val]) -> VmResult<Val> {
        self.env.call_function1(name, args)
    }
}
