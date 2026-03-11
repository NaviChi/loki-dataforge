@group(0) @binding(0) var<storage, read> data_in: array<u32>;
@group(0) @binding(1) var<storage, read_write> data_out: array<u32>;

@compute
@workgroup_size(64)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
    // Future GF(2^8) Reed-Solomon multiplications go here.
    // Baseline XOR scaffold:
    let index = global_id.x;
    data_out[index] = data_out[index] ^ data_in[index];
}
