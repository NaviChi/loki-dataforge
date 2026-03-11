use crate::error::{LokiDataForgeError, Result};
use std::borrow::Cow;

const MAX_WGPU_CHUNK_SIZE: usize = 32 * 1024 * 1024; // 32MB streaming cap to deeply optimize memory bounds

/// Executes a Galois Field GF(2^8) XOR calculation across stripes using WebGPU
/// compute shaders. This architecture degrades gracefully falling back through:
/// Apple Metal -> Vulkan -> DirectX 12 -> OpenGL.
pub async fn calculate_gf28_raid_syndromes(
    data_stripes: &[&[u8]],
    stripe_size: usize,
) -> Result<Vec<u8>> {
    if data_stripes.is_empty() {
        return Ok(vec![0u8; stripe_size]);
    }
    
    // Validate geometric bounds for u32 wgsl alignment
    if stripe_size % 4 != 0 {
        return Err(LokiDataForgeError::InvalidScanOptions(
            "Stripe size must be a tightly packed multiple of 4 bytes for wgpu array<u32> alignment".into()
        ));
    }

    // Utilize pure GPU architecture context mapping
    let instance = wgpu::Instance::default();
    
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
            compatible_surface: None,
        })
        .await
        .ok_or_else(|| {
            LokiDataForgeError::InvalidScanOptions(
                "No compatible GPU adapter found for wgpu compute offloading".into()
            )
        })?;

    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor::default(), None)
        .await
        .map_err(|e| {
            LokiDataForgeError::InvalidScanOptions(format!(
                "Failed to request logical device: {e}"
            ))
        })?;

    // Load optimized raid math bounds
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("raid_syndrome_shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("raid_gf28.wgsl"))),
    });

    // Deep memory optimization: Stream bounds in capped WGPU chunks instead of bulk VRAM locking
    let effective_chunk = stripe_size.min(MAX_WGPU_CHUNK_SIZE);
    let buffer_size = effective_chunk as wgpu::BufferAddress;
    
    let data_in_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("raid_data_in"),
        size: buffer_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    
    let data_out_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("raid_data_out"),
        size: buffer_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });
    
    let map_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("raid_map_buffer"),
        size: buffer_size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: None,
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: true },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: None,
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let compute_pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: None,
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "main",
    });

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: None,
        layout: &bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: data_in_buffer.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: data_out_buffer.as_entire_binding(),
            },
        ],
    });

    let mut final_result = vec![0u8; stripe_size];

    for chunk_start in (0..stripe_size).step_by(MAX_WGPU_CHUNK_SIZE) {
        let current_chunk_size = (stripe_size - chunk_start).min(MAX_WGPU_CHUNK_SIZE);
        
        // Directly bound the primary logical sequence for this chunk
        queue.write_buffer(&data_out_buffer, 0, &data_stripes[0][chunk_start..chunk_start + current_chunk_size]);

        // Multiplex all remaining stripes into parallel compute passes
        for stripe in data_stripes.iter().skip(1) {
            queue.write_buffer(&data_in_buffer, 0, &stripe[chunk_start..chunk_start + current_chunk_size]);
            
            let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
            {
                let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                    label: None,
                    timestamp_writes: None,
                });
                cpass.set_pipeline(&compute_pipeline);
                cpass.set_bind_group(0, &bind_group, &[]);
                let workgroup_count = (current_chunk_size as u32 / 4 / 64).max(1);
                cpass.dispatch_workgroups(workgroup_count, 1, 1);
            }
            queue.submit(Some(encoder.finish()));
        }

        // Flush GPU sequence into final mapping buffer for this chunk bound
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
        encoder.copy_buffer_to_buffer(&data_out_buffer, 0, &map_buffer, 0, current_chunk_size as wgpu::BufferAddress);
        queue.submit(Some(encoder.finish()));

        let buffer_slice = map_buffer.slice(..current_chunk_size as wgpu::BufferAddress);
        let (sender, receiver) = tokio::sync::oneshot::channel();
        buffer_slice.map_async(wgpu::MapMode::Read, move |v| {
            let _ = sender.send(v);
        });

        device.poll(wgpu::Maintain::Wait);

        if let Ok(Ok(())) = receiver.await {
            let data = buffer_slice.get_mapped_range();
            final_result[chunk_start..chunk_start + current_chunk_size].copy_from_slice(&data);
            drop(data);
            map_buffer.unmap();
        } else {
            return Err(LokiDataForgeError::InvalidScanOptions("Failed to map wgpu math buffer for raid chunk bounds limit extraction".into()));
        }
    }

    Ok(final_result)
}
