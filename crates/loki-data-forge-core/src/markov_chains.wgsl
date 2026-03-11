// Markov Chain Transition Analysis - wgpu Compute Shader
// Used to statistically model and destroy multi-layered ransomware obfuscation
// (e.g., base64 padding to bypass standard Shannon Entropy).

@group(0) @binding(0) var<storage, read> input_blocks: array<u32>;
@group(0) @binding(1) var<storage, read_write> transition_matrices: array<atomic<u32>>;
@group(0) @binding(2) var<storage, read_write> scores: array<f32>;

const BLOCK_SIZE: u32 = 4096u; // 4KB block processing
const MATRIX_SIZE: u32 = 256u * 256u; // 256x256 byte transition matrix per block

@compute
@workgroup_size(64)
fn calculate_markov_transitions(@builtin(global_invocation_id) global_id: vec3<u32>) {
    let block_idx = global_id.x;
    let num_blocks = arrayLength(&scores);
    
    if (block_idx >= num_blocks) {
        return;
    }

    let start_idx = block_idx * (BLOCK_SIZE / 4u);
    let matrix_offset = block_idx * MATRIX_SIZE;
    
    // We iterate over the 4KB block bytes
    // For simplicity in this wgsl PoC we use u32 words and extract bytes
    var prev_byte: u32 = 0u;
    var first: bool = true;
    
    // Track non-zero transition states
    var non_zero_transitions: u32 = 0u;

    for (var i: u32 = 0u; i < (BLOCK_SIZE / 4u); i = i + 1u) {
        let word = input_blocks[start_idx + i];
        
        for (var byte_idx: u32 = 0u; byte_idx < 4u; byte_idx = byte_idx + 1u) {
            let current_byte = (word >> (byte_idx * 8u)) & 0xFFu;
            
            if (!first) {
                let transition_idx = matrix_offset + (prev_byte * 256u) + current_byte;
                // Safely add to our probability matrix bucket
                let old_val = atomicAdd(&transition_matrices[transition_idx], 1u);
                if (old_val == 0u) {
                    non_zero_transitions = non_zero_transitions + 1u;
                }
            } else {
                first = false;
            }
            prev_byte = current_byte;
        }
    }
    
    // Heuristic: Highly compressed or encrypted data accesses nearly all 65,536 transitions.
    // Plaintext / MFT structures only transition between a predictable small subset.
    // We normalize this as a Float complexity score (1.0 = highly chaotic/encrypted, 0.0 = highly uniform).
    let max_possible = f32(BLOCK_SIZE - 1u);
    let complexity = f32(non_zero_transitions) / 65536.0; // Approximation scalar
    
    scores[block_idx] = complexity;
}
