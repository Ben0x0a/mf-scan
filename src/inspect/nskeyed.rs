//! NSKeyedArchiver resolver — decodes the flattened `$objects` graph back to a
//! logical key path such as `$.root.nested.inner`.
//!
//! Defines: [`nskeyed_path`] (the only public-within-inspect entry point).
//! Used by: `inspect::plist` (called from `inspect_binary_with` when the
//!   archive is detected as an NSKeyedArchiver).
//! Uses: `inspect::plist::Bplist` (read-only access via `pub(super)` helpers).
//!
//! ── Why this is a separate submodule ────────────────────────────────────────
//! The NSKeyedArchiver walk adds ~300 lines that are architecturally distinct
//! from both the binary-plist parser and the XML walker: it operates *on* a
//! parsed `Bplist`, not on raw bytes, and it carries its own UID-resolution
//! state. Keeping it separate preserves a single-concern boundary for `plist.rs`
//! while letting both files share the `Bplist` helpers (widened to `pub(super)`).
//!
//! ── NSKeyedArchiver mechanics (brief) ───────────────────────────────────────
//! An NSKeyedArchiver plist is a `bplist00` whose root dict has four reserved
//! keys: `$archiver`, `$version`, `$top` (a dict mapping logical root names to
//! UIDs), and `$objects` (a flat array; slot 0 is always the string `"$null"`).
//!
//! A **UID** is a bplist scalar with marker high-nibble `0x8`; its value is an
//! index into `$objects`.  All cross-references use UIDs; there are no direct
//! object-id references in the logical layer.
//!
//! An encoded **NSDictionary** / **NSMutableDictionary** is a bplist dict with
//! three keys: `NS.keys` (array of UIDs — each UID points to a string in
//! `$objects`), `NS.objects` (array of UIDs — positionally paired values), and
//! `$class` (ignored for path purposes).  An encoded **NSArray** / **NSMutableArray**
//! has `NS.objects` only; its elements render as `[i]`.
//!
//! A **wrapped scalar** (NSString, NSMutableString, NSData, NSValue) is encoded
//! as a bplist dict with `$class` plus one field (`NS.string`, `NS.data`, or
//! `NS.value`) whose bplist-object value IS the inner scalar object directly
//! (not wrapped in a further UID).  The match bytes live in that inner scalar,
//! so the resolver reports the *wrapper's* logical path (e.g. `$.root.s`) rather
//! than the un-reachable inner oid.
//!
//! ── Cycle / depth safety ────────────────────────────────────────────────────
//! We track a visited set of `$objects` indices (not raw oids) and cap the
//! recursion depth at `MAX_NK_DEPTH`. Any back-reference silently terminates
//! that branch; past the cap the subtree is abandoned. Neither can hang or
//! overflow the stack.
//!
//! ── Which class is reported ─────────────────────────────────────────────────
//! `NskeyedHit::class` carries the `$classname` of the logical object that
//! **directly holds the matched value**:
//!  - For a wrapped scalar hit: the wrapper's class (e.g. `"NSMutableString"`).
//!  - For a direct value hit in a container: the *container's* class
//!    (e.g. `"NSDictionary"`, `"NSArray"`).
//!  - `None` when the class object cannot be read (degrade gracefully).

use std::collections::HashSet;

use super::plist::Bplist;

/// Maximum recursion depth for the NSKeyedArchiver walk.
///
/// Prevents stack overflow on a crafted archive with a chain of nested dicts
/// deeper than anything a real archiver produces (which is typically < 10).
const MAX_NK_DEPTH: usize = 64;

/// The result of a successful NSKeyedArchiver path resolution.
///
/// WHY a struct rather than a bare tuple: the caller (`inspect_binary_with`)
/// needs both the path and the class atomically; a struct makes the contract
/// explicit and avoids positional confusion.
pub(super) struct NskeyedHit {
    /// Logical key-path segments (joined as `$.root.key[i]` by the caller).
    pub(super) path: Vec<String>,
    /// Foundation class name of the object that directly owns the matched value
    /// (e.g. `"NSMutableString"`, `"NSDictionary"`, `"NSArray"`).
    /// `None` when no `$class` entry can be read for the owning object.
    pub(super) class: Option<String>,
}

/// Resolve the logical NSKeyedArchiver path for the object at `offset` within
/// `bp`.
///
/// Returns `Some(hit)` when:
///   - the bplist root is a valid NSKeyedArchiver (`$archiver == "NSKeyedArchiver"`,
///     `$objects` array present, `$top` dict present), AND
///   - the matched object id can be reached by following UIDs from a `$top` entry.
///
/// Returns `None` on any structural anomaly; the caller then falls back to the
/// ordinary `path_to` walk.  Degrade, don't die — no panic, no hang.
pub(super) fn nskeyed_path(bp: &Bplist<'_>, offset: usize) -> Option<NskeyedHit> {
    let ctx = NskeyedCtx::build(bp)?;
    // Locate the raw object id that owns the byte at `offset`.
    let target_oid = bp.object_at_offset(offset)?;
    // Walk the logical graph to find a path to `target_oid`.
    ctx.find_path(target_oid)
}

// ── Internal context ─────────────────────────────────────────────────────────

/// Pre-parsed NSKeyedArchiver context: the `$objects` oid-list and the `$top`
/// entries, extracted once and reused for every match in the same file.
struct NskeyedCtx<'b> {
    bp: &'b Bplist<'b>,
    /// `objects_oids[i]` = the raw bplist oid that holds `$objects[i]`.
    objects_oids: Vec<usize>,
    /// `($top key name, UID value)` entries — usually just `[("root", 1)]`.
    top_entries: Vec<(String, usize)>,
}

impl<'b> NskeyedCtx<'b> {
    /// Build the context by inspecting the root dict of `bp`.
    ///
    /// Returns `None` unless the root dict has `$archiver == "NSKeyedArchiver"`,
    /// a `$objects` array, and a `$top` dict — this is the header-first detection
    /// mandated by the coding rules (content signature, not filename).
    fn build(bp: &'b Bplist<'b>) -> Option<Self> {
        // The root object (oid = bp.top) must be a dict.
        let root_pairs = bp.dict_pairs(bp.top_oid())?;

        // Read the four reserved keys from the root dict.
        let mut archiver_str: Option<String> = None;
        let mut objects_array_oid: Option<usize> = None;
        let mut top_dict_oid: Option<usize> = None;

        for (k_oid, v_oid) in &root_pairs {
            let key = bp.string_value(*k_oid)?;
            match key.as_str() {
                "$archiver" => archiver_str = bp.string_value(*v_oid),
                "$objects" => objects_array_oid = Some(*v_oid),
                "$top" => top_dict_oid = Some(*v_oid),
                _ => {}
            }
        }

        // Header-first detection: must be NSKeyedArchiver.
        if archiver_str.as_deref() != Some("NSKeyedArchiver") {
            return None;
        }
        let objects_oid = objects_array_oid?;
        let top_oid = top_dict_oid?;

        // Collect the oids that back each $objects slot.
        let objects_oids = bp.array_elements(objects_oid)?;

        // Collect $top entries: each value is a UID into $objects.
        let top_pairs = bp.dict_pairs(top_oid)?;
        let mut top_entries = Vec::with_capacity(top_pairs.len());
        for (k_oid, v_oid) in top_pairs {
            let name = bp.string_value(k_oid)?;
            // $top values are UIDs pointing into $objects.
            let uid = bp.uid_value(v_oid)?;
            top_entries.push((name, uid));
        }

        Some(Self {
            bp,
            objects_oids,
            top_entries,
        })
    }

    /// Translate a `$objects` index (UID value) to the raw bplist oid.
    ///
    /// Returns `None` when `idx` is out of range — crafted input guard.
    fn oid_for_uid(&self, uid: usize) -> Option<usize> {
        self.objects_oids.get(uid).copied()
    }

    /// Read the Foundation `$classname` string for the object at `oid`.
    ///
    /// HOW: a bplist dict is expected at `oid`; among its pairs we find the
    /// key `"$class"` whose value is a UID → a class-definition dict; from
    /// that dict we read the `"$classname"` key's string value.
    ///
    /// WHY: forensic context — knowing whether the matched value came from an
    /// `NSMutableString`, `NSData`, or `NSDictionary` helps triage quickly.
    /// Returns `None` on any deref failure; the caller omits the class field
    /// rather than failing (degrade, don't die).
    fn class_of(&self, oid: usize) -> Option<String> {
        let pairs = self.bp.dict_pairs(oid)?;
        // Locate the $class entry (a UID pointing to the class-definition dict).
        let class_uid_oid = pairs
            .iter()
            .find(|(k, _)| self.bp.string_value(*k).as_deref() == Some("$class"))
            .map(|(_, v)| *v)?;
        let class_uid = self.bp.uid_value(class_uid_oid)?;
        let class_def_oid = self.oid_for_uid(class_uid)?;
        // The class-definition dict has "$classname" → string.
        let def_pairs = self.bp.dict_pairs(class_def_oid)?;
        def_pairs
            .iter()
            .find(|(k, _)| self.bp.string_value(*k).as_deref() == Some("$classname"))
            .and_then(|(_, v)| self.bp.string_value(*v))
    }

    /// Walk the logical graph from every `$top` entry, searching for a path to
    /// the raw object id `target_oid`.
    fn find_path(&self, target_oid: usize) -> Option<NskeyedHit> {
        let mut result: Option<NskeyedHit> = None;
        let mut visited: HashSet<usize> = HashSet::new();

        for (name, uid) in &self.top_entries {
            let root_oid = self.oid_for_uid(*uid)?;
            let mut path = vec![name.clone()];
            // If the $top value itself is the target we have an exact hit.
            if root_oid == target_oid {
                let class = self.class_of(root_oid);
                return Some(NskeyedHit { path, class });
            }
            self.walk_logical(
                root_oid,
                target_oid,
                &mut path,
                &mut result,
                &mut visited,
                0,
            );
            if result.is_some() {
                return result;
            }
        }
        result
    }

    /// Recursively walk the decoded NSKeyedArchiver object graph.
    ///
    /// `current_oid` identifies the current bplist object. We use oid comparisons
    /// for the target check (since `object_at_offset` gives us a raw oid) and
    /// visit-tracking by `current_oid` to prevent cycles.
    ///
    /// Three hit kinds are recorded:
    ///  1. **Value hit** — `val_oid == target_oid` in an NSDictionary or NSArray.
    ///  2. **Key-name hit** — the key string oid in an NSDictionary's `NS.keys`
    ///     matches `target_oid` (the match landed on the key text itself).
    ///  3. **Wrapped-scalar hit** — the current node is neither a dict nor an array
    ///     (a leaf from the container perspective) but its raw bplist dict contains
    ///     `NS.string`, `NS.data`, or `NS.value` whose value oid equals `target_oid`.
    ///     The path recorded is the *wrapper's* path (already includes the owning
    ///     key / `[i]` segment), which is the meaningful forensic location.
    fn walk_logical(
        &self,
        current_oid: usize,
        target_oid: usize,
        path: &mut Vec<String>,
        result: &mut Option<NskeyedHit>,
        visited: &mut HashSet<usize>,
        depth: usize,
    ) {
        // Depth + cycle guards (degrade, don't die).
        if result.is_some() || depth > MAX_NK_DEPTH {
            return;
        }
        // We track visits by raw oid; that is safe because each $objects
        // slot maps to exactly one oid and the oid is what we compare for hits.
        if !visited.insert(current_oid) {
            return;
        }

        // Attempt to decode as an NSDictionary (NS.keys + NS.objects).
        if let Some((key_oids, val_oids)) = self.decode_ns_dictionary(current_oid) {
            let container_class = self.class_of(current_oid);
            for (key_uid_oid, val_uid_oid) in key_oids.iter().zip(val_oids.iter()) {
                // Each NS.keys element is a UID → $objects index → key string oid.
                let key_uid = self.bp.uid_value(*key_uid_oid);
                let key_str_oid = key_uid.and_then(|uid| self.oid_for_uid(uid));
                let key_str = key_str_oid
                    .and_then(|k_oid| self.bp.string_value(k_oid))
                    .unwrap_or_else(|| format!("#{key_uid_oid}"));

                // ── Key-name hit ──────────────────────────────────────────────
                // The match landed on the key string itself, not on a value.
                // WHY: a search result can hit a dictionary key name; without
                // this check the resolver would silently fall through and return
                // the unhelpful `$.$objects[N]` fallback.
                if key_str_oid.is_some_and(|k_oid| k_oid == target_oid) {
                    let mut p = path.clone();
                    p.push(key_str.clone());
                    *result = Some(NskeyedHit {
                        path: p,
                        // WHY container_class: the key belongs to this dict,
                        // so reporting the container's class is the natural
                        // forensic context.
                        class: container_class.clone(),
                    });
                    return;
                }

                // Each NS.objects element is a UID → $objects index → value oid.
                let Some(val_uid) = self.bp.uid_value(*val_uid_oid) else {
                    continue;
                };
                let Some(val_oid) = self.oid_for_uid(val_uid) else {
                    continue;
                };

                if val_oid == target_oid {
                    let mut p = path.clone();
                    p.push(key_str);
                    *result = Some(NskeyedHit {
                        path: p,
                        class: container_class.clone(),
                    });
                    return;
                }

                path.push(key_str);
                self.walk_logical(val_oid, target_oid, path, result, visited, depth + 1);
                path.pop();
                if result.is_some() {
                    return;
                }
            }
            return;
        }

        // Attempt to decode as an NSArray (NS.objects only).
        if let Some(elem_uid_oids) = self.decode_ns_array(current_oid) {
            let container_class = self.class_of(current_oid);
            for (i, elem_uid_oid) in elem_uid_oids.iter().enumerate() {
                let Some(elem_uid) = self.bp.uid_value(*elem_uid_oid) else {
                    continue;
                };
                let Some(elem_oid) = self.oid_for_uid(elem_uid) else {
                    continue;
                };

                let seg = format!("[{i}]");
                if elem_oid == target_oid {
                    let mut p = path.clone();
                    p.push(seg);
                    *result = Some(NskeyedHit {
                        path: p,
                        class: container_class.clone(),
                    });
                    return;
                }

                path.push(seg);
                self.walk_logical(elem_oid, target_oid, path, result, visited, depth + 1);
                path.pop();
                if result.is_some() {
                    return;
                }
            }
            return;
        }

        // ── Leaf node: check for a wrapped scalar ─────────────────────────────
        // HOW: if the current node is a bplist dict (but not an NSDictionary or
        // NSArray — no NS.keys / NS.objects), it may be a Foundation wrapper such
        // as NSMutableString ({ $class, NS.string: <string oid> }) or NSData
        // ({ $class, NS.data: <data oid> }).  In those cases the actual match
        // bytes are stored in the INNER oid referenced by the field value, which
        // is a direct bplist object reference (NOT a UID).
        //
        // WHY we check here and not earlier: the container decoders above already
        // returned `None` (no NS.keys/NS.objects), so we know we are at a leaf
        // from the logical-graph perspective.  We do not recurse further — the
        // field value is a scalar leaf, not a nested object — so no cycle risk
        // and O(1) per node.
        //
        // WHY we report the WRAPPER's path: the path already contains the owning
        // key/index segment (added by the parent before calling walk_logical), so
        // path at this point IS the wrapper's logical location.
        if let Some(pairs) = self.bp.dict_pairs(current_oid) {
            for (k_oid, inner_oid) in &pairs {
                let key = match self.bp.string_value(*k_oid) {
                    Some(k) => k,
                    None => continue,
                };
                // Only check the three known Foundation scalar-wrapper fields.
                if !matches!(key.as_str(), "NS.string" | "NS.data" | "NS.value") {
                    continue;
                }
                if *inner_oid == target_oid {
                    // Record a hit at the *wrapper's* path (current `path` already
                    // includes the key/[i] segment that led to this wrapper).
                    *result = Some(NskeyedHit {
                        path: path.clone(),
                        // WHY wrapper's class: the wrapper (e.g. NSMutableString)
                        // is the logical holder of the value from the archiver's
                        // perspective; its class is the most useful forensic label.
                        class: self.class_of(current_oid),
                    });
                    return;
                }
            }
        }
        // Leaf with no match — nothing to descend into.
    }

    /// Decode an NSDictionary object from `oid`: return `(NS.keys oids, NS.objects oids)`
    /// when the raw bplist dict at `oid` has both `NS.keys` and `NS.objects` arrays.
    ///
    /// WHY: NSDictionary encoding flattens keys and values into parallel arrays of
    /// UIDs rather than using the bplist dict's native key-value pairs.  We detect
    /// it by the presence of both magic field names in the raw bplist dict, then
    /// delegate key resolution to the caller.
    fn decode_ns_dictionary(&self, oid: usize) -> Option<(Vec<usize>, Vec<usize>)> {
        let pairs = self.bp.dict_pairs(oid)?;
        let mut ns_keys_oid: Option<usize> = None;
        let mut ns_objects_oid: Option<usize> = None;

        for (k_oid, v_oid) in &pairs {
            // Only look at plain string keys — $class, NS.keys, NS.objects.
            if let Some(key) = self.bp.string_value(*k_oid) {
                match key.as_str() {
                    "NS.keys" => ns_keys_oid = Some(*v_oid),
                    "NS.objects" => ns_objects_oid = Some(*v_oid),
                    _ => {}
                }
            }
        }

        let keys_oid = ns_keys_oid?;
        let objs_oid = ns_objects_oid?;
        let key_oids = self.bp.array_elements(keys_oid)?;
        let val_oids = self.bp.array_elements(objs_oid)?;
        Some((key_oids, val_oids))
    }

    /// Decode an NSArray object from `oid`: return the element oids from
    /// `NS.objects` when the dict at `oid` has `NS.objects` but NOT `NS.keys`.
    ///
    /// WHY: An NSArray encodes its elements as a flat `NS.objects` UID array with
    /// no parallel key array.  We distinguish it from NSDictionary by checking
    /// that `NS.keys` is absent — otherwise a dict with only `NS.objects` would
    /// be misread as an array.
    fn decode_ns_array(&self, oid: usize) -> Option<Vec<usize>> {
        let pairs = self.bp.dict_pairs(oid)?;
        let mut ns_keys_present = false;
        let mut ns_objects_oid: Option<usize> = None;

        for (k_oid, v_oid) in &pairs {
            if let Some(key) = self.bp.string_value(*k_oid) {
                match key.as_str() {
                    "NS.keys" => ns_keys_present = true,
                    "NS.objects" => ns_objects_oid = Some(*v_oid),
                    _ => {}
                }
            }
        }

        // Must have NS.objects and must NOT have NS.keys (that would be a dict).
        if ns_keys_present {
            return None;
        }
        let objs_oid = ns_objects_oid?;
        self.bp.array_elements(objs_oid)
    }
}
