//! WMV video inspector (media): classify by the ASF container GUID / extension.
//! Registered in `inspect::mod`; uses the shared `media::media_inspector!` macro.

use super::media_inspector;

media_inspector!(Wmv, "wmv", "media", ["wmv"], |c: &[u8]| c
    .starts_with(&super::ASF_GUID));
