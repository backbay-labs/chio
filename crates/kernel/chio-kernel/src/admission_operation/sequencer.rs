use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use super::*;

type MutationSequencers = HashMap<String, Weak<Mutex<()>>>;

#[derive(Clone)]
pub struct AdmissionMutationSequencer {
    inner: Arc<Mutex<()>>,
}

pub struct AdmissionMutationGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl AdmissionMutationSequencer {
    pub fn for_fence(fence: &StoreMutationFence) -> Result<Self, AdmissionOperationError> {
        validate_store_fence(fence)?;
        static SEQUENCERS: OnceLock<Mutex<MutationSequencers>> = OnceLock::new();

        let key = format!(
            "{}\0{}\0{}",
            fence.store_uuid, fence.lease_id, fence.owner_epoch
        );
        let registry = SEQUENCERS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut sequencers = registry
            .lock()
            .map_err(|_| AdmissionOperationError::MutationSequencerPoisoned)?;
        sequencers.retain(|_, sequencer| sequencer.strong_count() > 0);
        let inner = if let Some(sequencer) = sequencers.get(&key).and_then(Weak::upgrade) {
            sequencer
        } else {
            let sequencer = Arc::new(Mutex::new(()));
            sequencers.insert(key, Arc::downgrade(&sequencer));
            sequencer
        };
        Ok(Self { inner })
    }

    pub fn lock(&self) -> Result<AdmissionMutationGuard<'_>, AdmissionOperationError> {
        self.inner
            .lock()
            .map(|guard| AdmissionMutationGuard { _guard: guard })
            .map_err(|_| AdmissionOperationError::MutationSequencerPoisoned)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn identical_store_fences_share_one_mutation_sequence() {
        let fence = StoreMutationFence {
            store_uuid: "store-1".to_owned(),
            lease_id: "lease-1".to_owned(),
            owner_epoch: 1,
        };
        let first = AdmissionMutationSequencer::for_fence(&fence).expect("first sequencer");
        let second = AdmissionMutationSequencer::for_fence(&fence).expect("second sequencer");
        let held = first.lock().expect("first lock");
        let (sender, receiver) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            sender.send("waiting").expect("send waiting");
            let _guard = second.lock().expect("second lock");
            sender.send("acquired").expect("send acquired");
        });

        assert_eq!(receiver.recv().expect("receive waiting"), "waiting");
        assert!(receiver.recv_timeout(Duration::from_millis(25)).is_err());
        drop(held);
        assert_eq!(
            receiver
                .recv_timeout(Duration::from_secs(1))
                .expect("receive acquired"),
            "acquired"
        );
        waiter.join().expect("join waiter");
    }
}
