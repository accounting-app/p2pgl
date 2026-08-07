# Run everything
cargo test

# By crate
cargo test -p ledger
cargo test -p gl-node
cargo test -p p2p
cargo test -p security

# cargo test -p ledger \ 
# cargo test -p gl-node \ 
# cargo test -p p2p \ 
# cargo test -p security

# cargo test -p ledger && cargo test -p gl-node && cargo test -p p2p && cargo test -p security

# By module (within a crate)
cargo test -p ledger -- dag::
cargo test -p ledger -- hash::
cargo test -p ledger -- parse::
cargo test -p ledger -- validate::
cargo test -p ledger -- weights::
cargo test -p ledger -- read_model::
cargo test -p ledger -- serialize::
cargo test -p ledger -- service::
cargo test -p ledger -- verify::
cargo test -p ledger -- file_watcher::

cargo test -p gl-node -- config::
cargo test -p gl-node -- auth::
cargo test -p gl-node -- graphql::
cargo test -p gl-node -- health::
cargo test -p gl-node -- integration_test

cargo test -p p2p -- protocol::
cargo test -p p2p -- union_merge::
cargo test -p p2p -- gossip::
cargo test -p p2p -- anti_entropy::
cargo test -p p2p -- orphan_buffer::
cargo test -p p2p -- topic::
cargo test -p p2p -- node::

cargo test -p security -- signing::

# Single test (example)
cargo test -p ledger -- test_ct1_balanced_transaction_accepted
