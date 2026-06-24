use arcbox_virtio_core::error::{Result, VirtioError};

use super::VirtioFs;

type WriteBuffers = Vec<(usize, usize)>;
type PendingRequest = (u16, Vec<u8>, WriteBuffers);
type ResponseItem = (u16, std::result::Result<Vec<u8>, VirtioError>, WriteBuffers);

impl VirtioFs {
    /// Processes a single request queue and writes responses into guest memory.
    ///
    /// Returns a list of completed descriptor heads and their response lengths.
    pub fn process_queue(
        &mut self,
        queue_index: usize,
        memory: &mut [u8],
    ) -> Result<Vec<(u16, u32)>> {
        // First, collect all pending requests from the queue. Releases the
        // borrow on self.request_queues.
        let pending_requests = {
            let queue = self.request_queues.get_mut(queue_index).ok_or_else(|| {
                VirtioError::NotReady(format!("request queue {queue_index} not available"))
            })?;

            let mut requests: Vec<PendingRequest> = Vec::new();
            while let Some((head_idx, chain)) = queue.pop_avail() {
                let mut request_data = Vec::new();
                let mut write_buffers = Vec::new();

                for desc in chain {
                    let start = desc.addr as usize;
                    let end = start + desc.len as usize;
                    if end > memory.len() {
                        return Err(VirtioError::InvalidQueue(
                            "descriptor out of bounds".to_string(),
                        ));
                    }

                    if desc.is_write_only() {
                        write_buffers.push((start, desc.len as usize));
                    } else {
                        request_data.extend_from_slice(&memory[start..end]);
                    }
                }

                if write_buffers.is_empty() {
                    return Err(VirtioError::InvalidQueue(
                        "no writable descriptors for response".to_string(),
                    ));
                }

                requests.push((head_idx, request_data, write_buffers));
            }
            requests
        };

        // Process requests preserving avail ring order. Control requests
        // (INIT/DESTROY) must go through self.process_request() for session
        // state mutation. Normal requests can be dispatched in parallel via
        // handler when multiple are pending, but their results are collected
        // back into original order.

        let handler = self.handler.clone();
        let session_initialized = self.session.is_initialized();

        // Parallel dispatch is only safe when the entire batch contains
        // normal requests (no INIT/DESTROY) with valid FUSE headers (>= 40
        // bytes). If any control request is present, fall back to sequential
        // processing because pre-computing handler results for normal requests
        // around a DESTROY would violate avail ring ordering.
        let has_control = pending_requests.iter().any(|(_, data, _)| {
            if data.len() >= 8 {
                let op = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
                op == Self::FUSE_INIT || op == Self::FUSE_DESTROY
            } else {
                true // malformed → force sequential for proper error handling
            }
        });
        let all_valid = pending_requests.iter().all(|(_, data, _)| data.len() >= 40);
        let can_parallel = !has_control
            && all_valid
            && pending_requests.len() > 1
            && session_initialized
            && handler.is_some();

        let responses: Vec<ResponseItem> = if can_parallel {
            // All requests are normal with valid headers — safe to parallelize.
            let handler_ref = handler.as_ref().unwrap();
            use rayon::prelude::*;
            pending_requests
                .into_par_iter()
                .map(|(head_idx, data, bufs)| {
                    let response = handler_ref.handle_request(&data);
                    (head_idx, response, bufs)
                })
                .collect()
        } else {
            // Sequential: control ops present, malformed headers, or single request.
            pending_requests
                .into_iter()
                .map(|(head_idx, request_data, write_buffers)| {
                    let response = self.process_request(&request_data);
                    (head_idx, response, write_buffers)
                })
                .collect()
        };

        // Phase 2: Write responses into guest memory (sequential)
        // TODO(ABX-208): Use push_used_batch() for single interrupt notification
        let mut completions = Vec::with_capacity(responses.len());
        for (head_idx, response_result, write_buffers) in responses {
            let response = response_result?;
            let mut remaining = response.as_slice();
            let mut written = 0usize;

            for (start, len) in write_buffers {
                if remaining.is_empty() {
                    break;
                }

                let copy_len = len.min(remaining.len());
                memory[start..start + copy_len].copy_from_slice(&remaining[..copy_len]);
                remaining = &remaining[copy_len..];
                written += copy_len;
            }

            if !remaining.is_empty() {
                return Err(VirtioError::InvalidQueue(
                    "response buffer too small".to_string(),
                ));
            }

            completions.push((head_idx, written as u32));
        }

        Ok(completions)
    }
}
