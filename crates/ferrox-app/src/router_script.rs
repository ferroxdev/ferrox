//! The routing script: xray's Lua hook that answers a flow before the rule table does.
//!
//! The script reads the same context a rule does and returns an outbound tag; the modules it can
//! `require` are rebuilt here from this tree's matchers, not linked from a Lua runtime.

use std::net::IpAddr;
#[cfg(target_os = "ios")]
use std::path::PathBuf;
use std::sync::Arc;

/// What a script may call back into while it runs: the resolver a `xray.dns.Query` uses, and the
/// balancer table a `xray.router.PickOutbound` reads. Both are built once, so a call clones handles.
pub(crate) type Resolver = dyn Fn(&str, u16, bool, bool, bool) -> (Vec<IpAddr>, u32) + Send + Sync;
pub(crate) type Picker = dyn Fn(&str) -> Result<String, String> + Send + Sync;

#[derive(Clone)]
pub(crate) struct ScriptCallbacks {
    pub(crate) resolve: Arc<Resolver>,
    pub(crate) pick: Arc<Picker>,
}

impl std::fmt::Debug for ScriptCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptCallbacks")
    }
}

#[cfg(not(target_os = "ios"))]
mod lua;
#[cfg(not(target_os = "ios"))]
pub(crate) use lua::ScriptRouter;

/// iOS has no `os.execute` and marks `system` unavailable, so the vendored Lua 5.1 runtime does not build there; a config that names a script is refused in one line instead of failing to compile.
#[cfg(target_os = "ios")]
pub(crate) struct ScriptRouter;

#[cfg(target_os = "ios")]
impl std::fmt::Debug for ScriptRouter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ScriptRouter")
    }
}

#[cfg(target_os = "ios")]
impl ScriptRouter {
    pub(crate) fn parse_in(path: &str, _dirs: Vec<PathBuf>) -> Result<Self, String> {
        eprintln!(
            "routing script `{path}`: this platform has no Lua runtime, so the script is not run"
        );
        Ok(Self)
    }

    pub(crate) fn route(
        &self,
        _flow: &crate::router::Flow,
        _callbacks: &ScriptCallbacks,
    ) -> Result<Option<String>, String> {
        Ok(None)
    }
}
