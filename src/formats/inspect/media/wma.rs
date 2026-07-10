//! WMA audio inspector (media): classify by the ASF container GUID / extension
//! (shares the magic with WMV). Registered in `inspect::mod`; uses
//! `media::media_inspector!`.

use super::media_inspector;

media_inspector!(Wma, "wma", "media", ["wma"], |c: &[u8]| c
    .starts_with(&super::ASF_GUID));
