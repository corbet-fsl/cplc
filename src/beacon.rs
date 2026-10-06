//! Adapt existing durable publication ownership to the LGPL Beacon port.
use crate::{Policy, SnapshotKind, Storage};

impl<R: crbk::Storage, S: Storage, K: csgn::Store> cbcn::Publisher for Policy<R, S, K> {
    fn key_ring(&self) -> cbcn::Result<csgn::KeyRing> {
        Policy::key_ring(self)
            .cloned()
            .map_err(|_| cbcn::Error::Publication)
    }

    fn key_transitions(&self) -> cbcn::Result<Vec<cbcn::KeyTransition>> {
        Policy::key_transitions(self)
            .map(<[cbcn::KeyTransition]>::to_vec)
            .map_err(|_| cbcn::Error::Publication)
    }

    async fn publish(&mut self, kind: cbcn::Kind, now: u64) -> cbcn::Result<Vec<u8>> {
        let kind = match kind {
            cbcn::Kind::Settings => SnapshotKind::Settings,
            cbcn::Kind::Schema => SnapshotKind::Schema,
            cbcn::Kind::Communities => SnapshotKind::Communities,
            cbcn::Kind::Revocations => SnapshotKind::RevocationList,
            cbcn::Kind::SchemaVersions => SnapshotKind::SchemaVersions,
        };
        Policy::publish(self, kind, now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }

    async fn manifest(&mut self, now: u64) -> cbcn::Result<Vec<u8>> {
        self.trust_manifest(now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }

    async fn root_board(&mut self, now: u64) -> cbcn::Result<Option<Vec<u8>>> {
        self.root_board_publication(now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }

    async fn balance(&mut self, now: u64) -> cbcn::Result<Option<Vec<u8>>> {
        self.balance_publication(now)
            .await
            .map_err(|_| cbcn::Error::Publication)
    }
}
