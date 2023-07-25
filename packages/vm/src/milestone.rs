use std::collections::HashMap;

const WASM_V1: &str = "wasm_v1";

pub fn higher_than_wasm_v1(cur_block_num: u64, block_milestone: HashMap<String, u64>) -> bool {
    if let Some(value) = block_milestone.get(WASM_V1) {
        if cur_block_num >= *value {
            println!(
                "higher_than_wasm_v1, cur_block_num:{}, milestone:{}",
                cur_block_num, value
            );
            return true;
        }
    }

    return false;
}
