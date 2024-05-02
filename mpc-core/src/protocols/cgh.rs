use std::marker::PhantomData;

pub struct CGHProtocol<F> {
    field: PhantomData<F>,
}
