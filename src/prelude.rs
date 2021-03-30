//
// Use these dummy mods as a trick to re-export multiple traits at once
//
// extern crate alloc;
#[cfg(not(feature = "std"))]
mod reexports {
    extern crate alloc;
    pub use alloc::string::String;
    pub use alloc::vec::Vec;
}

#[cfg(feature = "std")]
mod reexports {
    pub use std::string::String;
    pub use std::vec::Vec;
}

pub use self::reexports::*;
