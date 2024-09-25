/// try-finally/defer analogue to invoke some logic when a scope ends
pub(crate) struct Deferred(pub Box<dyn Fn() -> ()>);

impl Drop for Deferred {
    fn drop(&mut self) {
        let _ = (self.0)();
    }
}
