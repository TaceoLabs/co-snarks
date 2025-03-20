use rayon::ThreadPoolBuilder;

pub fn spawn_pool(op: impl FnOnce() + Send + 'static) {
    std::thread::spawn(|| {
        let pool = ThreadPoolBuilder::new()
            .num_threads(4)
            .use_current_thread()
            .build()
            .unwrap();
        pool.install(op);
    });
}
