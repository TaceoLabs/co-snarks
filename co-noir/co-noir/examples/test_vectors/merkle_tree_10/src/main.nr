use dep::poseidon;

fn main(leaves: [Field; 1024]) -> pub Field {
    let mut vector: Vec<Field> = Vec::from_slice(leaves);
    let mut depth = 10;

    for _ in 0..depth {
        let mut next_level: Vec<Field> = Vec::new();
        let len = vector.len();

        for k in 0..len {
            if k % 2 == 0 {
                let left = vector.get(k);
                let right = if k + 1 < len { vector.get(k + 1) } else { left }; // else shouldnt happen
                let parent = hash([left, right]);
                next_level.push(parent);
            }
        }

        vector = next_level;
    }

    vector.get(0)
}

fn hash(nodes: [Field; 2]) -> Field {
    poseidon::bn254::hash_2(nodes)
}
