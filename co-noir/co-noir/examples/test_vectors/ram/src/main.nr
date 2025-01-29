fn main(mut array: [Field; 3], index: u32, element: Field) -> pub Field {
    array[index] = element;
    array[0] + array[1] + array[2]
}
