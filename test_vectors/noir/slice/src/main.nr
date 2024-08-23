use dep::std;

fn flatten_slice(slice: [Field]) -> Field {
    slice[0] + slice[1]
}

fn main(vk: [Field; 2]) {
    assert(vk[0] + flatten_slice(vk.as_slice()) == 4);
}
