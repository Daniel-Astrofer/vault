//! Compile-time safeguards for the only supported deployment profile.
#[cfg(not(feature = "production"))]
compile_error!("kerosene-vault only supports the production build");

#[cfg(feature = "dealer_lab")]
compile_error!("dealer key generation has been removed; use distributed_wire DKG");
