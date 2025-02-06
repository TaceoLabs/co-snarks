use dep::poseidon;
// use std::hash::poseidon;

fn main(leaves: [Field; 4]) -> pub Field {
    let mut vector: Vec<Field> = Vec::from_slice(leaves);
    let mut depth = 2;

    for _ in 0..depth {
        let mut next_level: Vec<Field> = Vec::new();
        let len = vector.len();

        for k in 0..len {
            if k % 2 == 0 {
                let left = vector.get(k);
                let right = vector.get(k + 1) ; 
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
