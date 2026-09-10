//! Observe initialized Argon2 workspace bytes before deallocation in this binary only.
//! This does not test erasure of registers, stack temporaries, swap, or crash dumps.

#[path = "../src/secret"]
mod secret {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        cell::Cell,
    };

    use argon2::Block;
    use intentkey_core::owner::SecretErrorCode;

    // Compile the actual envelope implementation, not a duplicate of the KDF seam.
    #[path = "native_format.rs"]
    mod native_format;

    #[derive(Clone, Copy, Default)]
    struct Observation {
        enabled: bool,
        fail_allocation: bool,
        allocations: usize,
        releases: usize,
        dirty_releases: usize,
    }

    thread_local! {
        // Constant-initialized, non-dropping TLS: allocator callbacks never allocate,
        // lock, panic, or share observations between concurrent test threads.
        static OBSERVATION: Cell<Observation> = const { Cell::new(Observation {
            enabled: false,
            fail_allocation: false,
            allocations: 0,
            releases: 0,
            dirty_releases: 0,
        }) };
    }

    struct ObservedAllocator;

    const fn is_workspace(layout: Layout) -> bool {
        layout.size() == 65_536 * size_of::<Block>() && layout.align() == align_of::<Block>()
    }

    // SAFETY: allocations retain System's layout/alignment and ownership contracts.
    // Inspection happens only before System.dealloc, never after memory is freed.
    unsafe impl GlobalAlloc for ObservedAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if is_workspace(layout) {
                let fail = OBSERVATION.with(|state| {
                    let mut observation = state.get();
                    if observation.enabled {
                        observation.allocations += 1;
                        state.set(observation);
                    }
                    observation.enabled && observation.fail_allocation
                });
                if fail {
                    return std::ptr::null_mut();
                }
                // SAFETY: the valid allocation layout is forwarded unchanged. All
                // bytes are initialized so even early-error releases can be read.
                return unsafe { System.alloc_zeroed(layout) };
            }
            // SAFETY: forwarding the caller's valid layout to System.
            unsafe { System.alloc(layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if is_workspace(layout) {
                // SAFETY: alloc initializes every workspace byte to zero.
                return unsafe { self.alloc(layout) };
            }
            // SAFETY: forwarding the caller's valid layout to System.
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            if is_workspace(layout) {
                OBSERVATION.with(|state| {
                    let mut observation = state.get();
                    if observation.enabled {
                        // SAFETY: this allocation is still live and exclusively
                        // owned by this deallocation call. Our allocator initialized
                        // its entire extent; Block has no uninitialized padding.
                        let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
                        observation.releases += 1;
                        observation.dirty_releases +=
                            usize::from(bytes.iter().any(|&byte| byte != 0));
                        state.set(observation);
                    }
                });
            }
            // SAFETY: ptr is released exactly once with its original layout, after
            // the inspection borrow has ended. No pointer or bytes are retained.
            unsafe { System.dealloc(ptr, layout) };
        }
    }

    #[global_allocator]
    static ALLOCATOR: ObservedAllocator = ObservedAllocator;

    fn observe<T>(fail_allocation: bool, action: impl FnOnce() -> T) -> (T, Observation) {
        OBSERVATION.with(|state| {
            state.set(Observation {
                enabled: true,
                fail_allocation,
                ..Observation::default()
            });
        });
        let result = action();
        let observation = OBSERVATION.with(|state| state.replace(Observation::default()));
        (result, observation)
    }

    fn assert_wiped(observation: Observation) {
        assert_eq!(
            observation.allocations, 1,
            "observe the fixed 64 MiB workspace"
        );
        assert_eq!(observation.releases, 1, "workspace released before return");
        assert_eq!(
            observation.dirty_releases, 0,
            "workspace backing must be wiped before release"
        );
    }

    #[test]
    fn native_workspace_is_wiped_on_success_and_authentication_error()
    -> Result<(), Box<dyn std::error::Error>> {
        let (envelope, observation) = observe(false, || {
            native_format::Envelope::create(b"harmless-audit-fixture")
        });
        let envelope = envelope?;
        assert_wiped(observation);
        let ciphertext = envelope.encode(b"synthetic public payload", 1)?;

        let (decoded, observation) = observe(false, || {
            native_format::Envelope::decode(b"harmless-audit-fixture", &ciphertext)
        });
        let (_, payload, generation) = decoded?;
        assert_wiped(observation);
        assert_eq!(payload.as_slice(), b"synthetic public payload");
        assert_eq!(generation, 1);

        let (wrong, observation) = observe(false, || {
            native_format::Envelope::decode(b"different-public-fixture", &ciphertext)
        });
        assert!(matches!(wrong, Err(SecretErrorCode::AuthenticationFailed)));
        assert_wiped(observation);
        Ok(())
    }

    #[test]
    fn native_workspace_allocation_failure_is_a_generic_error() {
        let (result, observation) = observe(true, || {
            native_format::Envelope::create(b"harmless-audit-fixture")
        });
        assert!(matches!(result, Err(SecretErrorCode::Unavailable)));
        assert_eq!(observation.allocations, 1);
        assert_eq!(observation.releases, 0);
    }
}
