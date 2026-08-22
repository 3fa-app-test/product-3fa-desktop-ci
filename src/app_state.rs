//! Total vault lifecycle state machine.
//!
//! Illegal events are rejected without mutating state. Create and unlock issue
//! generation-stamped tokens; lock and dispose advance the generation, so a
//! completion from an invalidated operation can never reopen the vault.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Phase {
    Loading,
    Setup,
    Creating,
    Locked,
    Unlocking,
    Unlocked,
    Disposed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Operation {
    Create,
    Unlock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OperationToken {
    generation: u64,
    operation: Operation,
}

impl OperationToken {
    pub fn generation(self) -> u64 {
        self.generation
    }

    pub fn operation(self) -> Operation {
        self.operation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Signal {
    InitializedEmpty,
    InitializedVault,
    BeginCreate,
    BeginUnlock,
    OperationSucceeded(OperationToken),
    OperationFailed(OperationToken),
    Lock,
    Dispose,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionResult {
    pub accepted: bool,
    pub token: Option<OperationToken>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultLifecycle {
    phase: Phase,
    generation: u64,
    active: Option<OperationToken>,
}

impl Default for VaultLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultLifecycle {
    pub const fn new() -> Self {
        Self {
            phase: Phase::Loading,
            generation: 0,
            active: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn active_operation(&self) -> Option<OperationToken> {
        self.active
    }

    pub fn initialize(&mut self, vault_exists: bool) -> bool {
        self.apply(if vault_exists {
            Signal::InitializedVault
        } else {
            Signal::InitializedEmpty
        })
        .accepted
    }

    pub fn begin_create(&mut self) -> Option<OperationToken> {
        self.apply(Signal::BeginCreate).token
    }

    pub fn begin_unlock(&mut self) -> Option<OperationToken> {
        self.apply(Signal::BeginUnlock).token
    }

    pub fn complete(&mut self, token: OperationToken, succeeded: bool) -> bool {
        self.apply(if succeeded {
            Signal::OperationSucceeded(token)
        } else {
            Signal::OperationFailed(token)
        })
        .accepted
    }

    pub fn lock(&mut self) -> bool {
        self.apply(Signal::Lock).accepted
    }

    pub fn dispose(&mut self) -> bool {
        self.apply(Signal::Dispose).accepted
    }

    pub fn owns_generation(&self, generation: u64) -> bool {
        self.phase == Phase::Unlocked && self.generation == generation
    }

    /// The total transition function. Every signal is defined in every phase.
    pub fn apply(&mut self, signal: Signal) -> TransitionResult {
        let rejected = TransitionResult {
            accepted: false,
            token: None,
        };
        let accepted = TransitionResult {
            accepted: true,
            token: None,
        };
        match signal {
            Signal::InitializedEmpty => {
                if self.phase != Phase::Loading {
                    return rejected;
                }
                self.phase = Phase::Setup;
                accepted
            }
            Signal::InitializedVault => {
                if self.phase != Phase::Loading {
                    return rejected;
                }
                self.phase = Phase::Locked;
                accepted
            }
            Signal::BeginCreate => {
                if self.phase != Phase::Setup {
                    return rejected;
                }
                let Some(next_generation) = self.generation.checked_add(1) else {
                    // Fail closed instead of ever reusing a generation-stamped
                    // token after the finite counter is exhausted.
                    return rejected;
                };
                self.generation = next_generation;
                let token = OperationToken {
                    generation: self.generation,
                    operation: Operation::Create,
                };
                self.active = Some(token);
                self.phase = Phase::Creating;
                TransitionResult {
                    accepted: true,
                    token: Some(token),
                }
            }
            Signal::BeginUnlock => {
                if self.phase != Phase::Locked {
                    return rejected;
                }
                let Some(next_generation) = self.generation.checked_add(1) else {
                    return rejected;
                };
                self.generation = next_generation;
                let token = OperationToken {
                    generation: self.generation,
                    operation: Operation::Unlock,
                };
                self.active = Some(token);
                self.phase = Phase::Unlocking;
                TransitionResult {
                    accepted: true,
                    token: Some(token),
                }
            }
            Signal::OperationSucceeded(token) | Signal::OperationFailed(token) => {
                if self.active != Some(token) {
                    return rejected;
                }
                let expected = match token.operation {
                    Operation::Create => Phase::Creating,
                    Operation::Unlock => Phase::Unlocking,
                };
                if self.phase != expected {
                    return rejected;
                }
                self.active = None;
                self.phase = match signal {
                    Signal::OperationSucceeded(_) => Phase::Unlocked,
                    Signal::OperationFailed(_) => match token.operation {
                        Operation::Create => Phase::Setup,
                        Operation::Unlock => Phase::Locked,
                    },
                    _ => unreachable!("the outer pattern limits this branch"),
                };
                accepted
            }
            Signal::Lock => {
                if self.phase == Phase::Disposed {
                    return rejected;
                }
                self.generation = self.generation.saturating_add(1);
                self.active = None;
                self.phase = match self.phase {
                    Phase::Loading => Phase::Loading,
                    Phase::Setup => Phase::Setup,
                    Phase::Creating | Phase::Locked | Phase::Unlocking | Phase::Unlocked => {
                        Phase::Locked
                    }
                    Phase::Disposed => Phase::Disposed,
                };
                accepted
            }
            Signal::Dispose => {
                if self.phase == Phase::Disposed {
                    return rejected;
                }
                self.generation = self.generation.saturating_add(1);
                self.active = None;
                self.phase = Phase::Disposed;
                accepted
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_unlock_have_explicit_legal_paths() {
        let mut create = VaultLifecycle::new();
        assert!(create.initialize(false));
        let token = create.begin_create().unwrap();
        assert_eq!(create.phase(), Phase::Creating);
        assert!(create.complete(token, true));
        assert_eq!(create.phase(), Phase::Unlocked);

        let mut unlock = VaultLifecycle::new();
        assert!(unlock.initialize(true));
        let token = unlock.begin_unlock().unwrap();
        assert!(unlock.complete(token, true));
        assert_eq!(unlock.phase(), Phase::Unlocked);
    }

    #[test]
    fn lock_invalidates_in_flight_operations() {
        let mut state = VaultLifecycle::new();
        state.initialize(true);
        let token = state.begin_unlock().unwrap();
        assert!(state.lock());
        assert!(!state.complete(token, true));
        assert_eq!(state.phase(), Phase::Locked);
        assert!(!state.owns_generation(token.generation()));
    }

    #[test]
    fn dispose_is_absorbing_for_every_signal() {
        let mut state = VaultLifecycle::new();
        assert!(state.dispose());
        let stale = OperationToken {
            generation: 0,
            operation: Operation::Unlock,
        };
        for signal in [
            Signal::InitializedEmpty,
            Signal::InitializedVault,
            Signal::BeginCreate,
            Signal::BeginUnlock,
            Signal::OperationSucceeded(stale),
            Signal::OperationFailed(stale),
            Signal::Lock,
            Signal::Dispose,
        ] {
            assert!(!state.apply(signal).accepted);
            assert_eq!(state.phase(), Phase::Disposed);
        }
    }

    #[test]
    fn illegal_inputs_are_rejected_without_mutation() {
        let mut state = VaultLifecycle::new();
        let initial = state.clone();
        assert!(!state.apply(Signal::BeginCreate).accepted);
        assert!(!state.apply(Signal::BeginUnlock).accepted);
        assert_eq!(state, initial);
        assert_eq!(state.active_operation(), None);
    }

    #[test]
    fn exhausted_generation_never_reuses_an_operation_token() {
        let mut state = VaultLifecycle {
            phase: Phase::Locked,
            generation: u64::MAX - 1,
            active: None,
        };
        let final_token = state.begin_unlock().unwrap();
        assert_eq!(final_token.generation(), u64::MAX);

        assert!(state.lock());
        assert_eq!(state.generation(), u64::MAX);
        assert_eq!(state.begin_unlock(), None);
        assert!(!state.complete(final_token, true));
        assert_eq!(state.phase(), Phase::Locked);
    }
}
