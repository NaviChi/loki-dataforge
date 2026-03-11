use std::borrow::Cow;
use wgpu::util::DeviceExt;

use crate::error::{LokiDataForgeError, Result};

/// Advanced Markov Transition Analysis utilizing wgpu for deep ransomware
/// obfuscation modeling.
/// Parses thousands of blocks mathematically assessing Kolmogorov complexity maps.
pub async fn calculate_markov_obfuscation(blocks: &[u8], block_size: usize) -> Result<Vec<f32>> {
    let instance = wgpu::Instance::default();
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions::default())
        .await
        .ok_or_else(|| LokiDataForgeError::ComputeEngine("Failed to find appropriate WGPU adapter for Markov Chain analysis".to_string()))?;

    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor::default(), None)
        .await
        .map_err(|e| LokiDataForgeError::ComputeEngine(e.to_string()))?;

    let num_blocks = blocks.len() / block_size;
    
    // Shader compilation
    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("Markov Transition Shader"),
        source: wgpu::ShaderSource::Wgsl(Cow::Borrowed(include_str!("markov_chains.wgsl"))),
    });

    // 1. Input blocks buffer
    let input_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("Markov Input Blocks"),
        contents: blocks,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
    });

    // 2. Transition matrix buffer (atomic u32 counters) - 256x256 elements per block
    let matrix_size = (num_blocks * 256 * 256 * 4) as wgpu::BufferAddress;
    let transition_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("Transition Matrices"),
        size: matrix_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    // 3. Scores output buffer
    let scores_size = (num_blocks * std::mem::size_of::<f32>()) as wgpu::BufferAddress;
    let scores_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("Markov Scores"),
        size: scores_size,
        usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_SRC,
        mapped_at_creation: false,
    });
    
    let scores_staging_buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("Scores Staging"),
        size: scores_size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("Markov Bind Group Layout"),
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
            wgpu::BindGroupLayoutEntry {
                binding: 2,
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

    let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("Markov Bind Group"),
        layout: &bind_group_layout,
        entries: &[
            wgpu::BindGroupEntry { binding: 0, resource: input_buffer.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 1, resource: transition_buffer.as_entire_binding() },
            wgpu::BindGroupEntry { binding: 2, resource: scores_buffer.as_entire_binding() },
        ],
    });

    let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("Markov Pipeline Layout"),
        bind_group_layouts: &[&bind_group_layout],
        push_constant_ranges: &[],
    });

    let pipeline = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("Markov Pipeline"),
        layout: Some(&pipeline_layout),
        module: &shader,
        entry_point: "calculate_markov_transitions",
        compilation_options: Default::default(),
        cache: None,
    });

    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
    
    // Clear the transition buffer (important for atomic counters)
    encoder.clear_buffer(&transition_buffer, 0, None);

    {
        let mut cpass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("Markov Compute Pass"),
            timestamp_writes: None,
        });
        cpass.set_pipeline(&pipeline);
        cpass.set_bind_group(0, &bind_group, &[]);
        let workgroups = ((num_blocks as f32) / 64.0).ceil() as u32;
        cpass.dispatch_workgroups(workgroups.max(1), 1, 1);
    }

    encoder.copy_buffer_to_buffer(&scores_buffer, 0, &scores_staging_buffer, 0, scores_size);
    queue.submit(Some(encoder.finish()));

    let buffer_slice = scores_staging_buffer.slice(..);
    let (sender, receiver) = flume::bounded(1);
    buffer_slice.map_async(wgpu::MapMode::Read, move |v| sender.send(v).unwrap());

    device.poll(wgpu::Maintain::Wait);
    receiver.recv_async().await.unwrap().map_err(|e| LokiDataForgeError::ComputeEngine(e.to_string()))?;

    let data = buffer_slice.get_mapped_range();
    let result: Vec<f32> = bytemuck::cast_slice(&data).to_vec();
    drop(data);
    scores_staging_buffer.unmap();

    Ok(result)
}
