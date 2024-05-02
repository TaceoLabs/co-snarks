use std::marker::PhantomData;

pub struct SpdzProtocol<F> {
    field: PhantomData<F>,
}
