use tracing::{span, Subscriber};
use tracing_subscriber::{
    filter::{self, FilterFn},
    layer,
    registry::LookupSpan,
    Layer,
};

use std::{
    fs::File,
    io::Write,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAGIC_PROFILING_NUMBER: &str = "flamegraph_timing_492df4687a2732ad9905ccaa42b63780bdb62fb0";
const MAGIC_FLUSH_NUMBER: &str = "flamegraph_flushing_492df4687a2732ad9905ccaa42b63780bdb62fb0";

enum IoConfig {
    StdIo(Arc<Mutex<Vec<String>>>),
    File(Arc<Mutex<(Vec<String>, File)>>),
}

pub struct FlamegraphLayer(IoConfig);

#[macro_export]
macro_rules! start_sample {
    ($name: expr) => {
        tracing::debug_span!(
            "flamegraph_timing_492df4687a2732ad9905ccaa42b63780bdb62fb0",
            component = $name
        )
        .entered()
    };
}

#[macro_export]
macro_rules! flush_profiling {
    () => {
        tracing::event!(name: "flamegraph_flushing_492df4687a2732ad9905ccaa42b63780bdb62fb0", Level::DEBUG, "pls flush me");
    };
}

#[macro_export]
macro_rules! end_profiling {
    () => {
        tracing::event!(name: "flamegraph_flushing_492df4687a2732ad9905ccaa42b63780bdb62fb0", Level::DEBUG, "pls flush me");
    };
}

#[derive(Debug)]
struct FlameGraphStorage {
    name: String,
    enter_time: Instant,
    children_time: Duration,
}

impl FlameGraphStorage {
    pub fn new(name: String) -> Self {
        Self {
            name,
            // init the time. As soon as we call on_span_enter we
            // set to the correct time
            enter_time: Instant::now(),
            children_time: Duration::from_secs(0),
        }
    }
}
struct FlameGraphVisitor<'a>(&'a mut String);

impl tracing::field::Visit for FlameGraphVisitor<'_> {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "component" {
            *self.0 = value.to_string()
        } else {
            panic!("something else: {}", field.name())
        }
    }

    fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {
        // nothing todo
    }
}

impl<S> Layer<S> for FlamegraphLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &span::Attributes<'_>, id: &span::Id, ctx: layer::Context<'_, S>) {
        if attrs.metadata().name() == MAGIC_PROFILING_NUMBER {
            let mut component = String::new();
            let mut visitor = FlameGraphVisitor(&mut component);
            attrs.record(&mut visitor);

            // And stuff it in our newtype.
            let storage = FlameGraphStorage::new(component);

            // Get a reference to the internal span data
            let span = ctx.span(id).expect("span must be here");
            // Get the special place where tracing stores custom data
            let mut extensions = span.extensions_mut();
            // And store our data
            extensions.insert::<FlameGraphStorage>(storage);
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, _ctx: layer::Context<'_, S>) {
        if event.metadata().name() == MAGIC_FLUSH_NUMBER {
            match &self.0 {
                IoConfig::StdIo(inner) => {
                    let mut messages = Vec::with_capacity(2048);
                    let mut inner = inner.lock().expect("not poisoned");
                    std::mem::swap(&mut messages, &mut inner);
                    println!("{}", messages.join("\n"));
                }
                IoConfig::File(inner) => {
                    let mut messages = Vec::with_capacity(2048);
                    let mut inner = inner.lock().expect("not poisoned");
                    std::mem::swap(&mut messages, &mut inner.0);
                    if let Err(err) = inner.1.write_all(messages.join("\n").as_bytes()) {
                        eprintln!("could not write to file during flamegraph creation!");
                        eprintln!("{err:?}");
                    }
                }
            }
        }
    }

    fn on_enter(&self, id: &span::Id, ctx: layer::Context<'_, S>) {
        let span = ctx.span(id).expect("span must be here");
        let mut extensions = span.extensions_mut();
        let storage = extensions
            .get_mut::<FlameGraphStorage>()
            .expect("does have storage on enter");
        storage.enter_time = Instant::now();
    }

    fn on_exit(&self, id: &span::Id, ctx: layer::Context<'_, S>) {
        let span = ctx.span(id).expect("span must be here");
        // we need to drop the reference to extensions,
        // otherwise we deadlock when we try to update
        // the parents children time
        let (elapsed_time, children_time) = {
            let extensions = span.extensions();
            let storage = extensions
                .get::<FlameGraphStorage>()
                .expect("does have storage on exit");
            (storage.enter_time.elapsed(), storage.children_time)
        };

        // find the first parent that is also flamegraph span
        if let Some(parent) = span
            .scope()
            .skip(1)
            .find(|p| p.name() == MAGIC_PROFILING_NUMBER)
        {
            let mut extension_parent = parent.extensions_mut();
            let storage_parent = extension_parent
                .get_mut::<FlameGraphStorage>()
                .expect("parent must have storage");
            storage_parent.children_time += elapsed_time;
        }

        let trace = span
            .scope()
            .from_root()
            .filter_map(|p| {
                if p.name() == MAGIC_PROFILING_NUMBER {
                    let extensions = p.extensions();
                    let parent_component = extensions
                        .get::<FlameGraphStorage>()
                        .expect("parent must have storage");
                    Some(parent_component.name.clone())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join(";");
        let own_time = elapsed_time - children_time;
        let to_write = format!("{trace} {}", own_time.as_nanos());
        match &self.0 {
            IoConfig::StdIo(inner) => {
                let mut messages = inner.lock().expect("lock not poisoned");
                messages.push(to_write);
            }
            IoConfig::File(inner) => {
                let mut messages = inner.lock().expect("lock not poisoned");
                messages.0.push(to_write);
            }
        }
    }
}

impl FlamegraphLayer {
    pub fn stdio<S>() -> filter::Filtered<Self, FilterFn, S>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        Self: 'static + Sized,
    {
        let stdio_config = Arc::new(Mutex::new(Vec::with_capacity(2048)));
        FlamegraphLayer(IoConfig::StdIo(stdio_config)).with_filter(filter::filter_fn(|metadata| {
            metadata.name() == MAGIC_PROFILING_NUMBER || metadata.name() == MAGIC_FLUSH_NUMBER
        }))
    }

    pub fn file<S>(file: File) -> filter::Filtered<Self, FilterFn, S>
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
        Self: 'static,
    {
        let file_config = Arc::new(Mutex::new((Vec::with_capacity(2048), file)));
        FlamegraphLayer(IoConfig::File(file_config)).with_filter(filter::filter_fn(|metadata| {
            metadata.name() == MAGIC_PROFILING_NUMBER || metadata.name() == MAGIC_FLUSH_NUMBER
        }))
    }
}
