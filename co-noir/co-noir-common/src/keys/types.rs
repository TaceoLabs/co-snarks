use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
pub struct ActiveRegionData {
    pub ranges: Vec<(usize, usize)>, // active ranges [start_i, end_i) of the execution trace
    pub idxs: Vec<usize>,            // full set of poly indices corresposponding to active ranges
    pub current_end: usize,          // end of last range; for ensuring monotonicity of ranges
}
impl ActiveRegionData {
    pub fn new() -> Self {
        Self {
            ranges: Vec::new(),
            idxs: Vec::new(),
            current_end: 0,
        }
    }

    pub fn add_range(&mut self, start: usize, end: usize) {
        assert!(
            start >= self.current_end,
            "Ranges should be non-overlapping and increasing"
        );

        self.ranges.push((start, end));
        self.idxs.extend(start..end);
        self.current_end = end;
    }

    pub fn get_ranges(&self) -> &Vec<(usize, usize)> {
        &self.ranges
    }

    pub fn get_idx(&self, idx: usize) -> usize {
        self.idxs[idx]
    }

    pub fn get_range(&self, idx: usize) -> (usize, usize) {
        self.ranges[idx]
    }

    pub fn size(&self) -> usize {
        self.idxs.len()
    }

    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }
}
