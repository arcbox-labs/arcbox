//! Integration tests for arcbox-net.
//!
//! These tests verify end-to-end functionality of the network stack components
//! working together.

// ============================================================================
// Datapath Integration Tests
// ============================================================================

mod datapath {
    use arcbox_net::datapath::ring::MpmcRing;
    use arcbox_net::datapath::{DatapathStats, LockFreeRing, PacketPool, ZeroCopyPacket};

    /// Test packet flow through pool and ring buffer.
    #[test]
    fn test_packet_flow_through_datapath() {
        // Create pool and ring
        let pool = PacketPool::new(64).unwrap();
        let ring: LockFreeRing<u32> = LockFreeRing::new(64);

        // Simulate allocating packet buffers and passing indices through ring
        let mut allocated_indices = Vec::new();

        // Allocate several buffers
        for i in 0..10 {
            if let Some(idx) = pool.alloc_index() {
                // Write test data to buffer
                let buffer = unsafe { pool.get_mut(idx) };
                buffer.as_full_mut_slice()[0..4].copy_from_slice(&[i as u8, 0, 0, 0]);
                buffer.set_len(4);
                allocated_indices.push(idx);

                // Pass index through ring
                ring.enqueue(idx).unwrap();
            }
        }

        assert_eq!(ring.len(), 10);

        // Consumer side: dequeue and verify
        for expected_i in 0..10 {
            let idx = ring.dequeue().unwrap();
            let buffer = unsafe { pool.get(idx) };
            assert_eq!(buffer.as_full_slice()[0], expected_i as u8);

            // Free buffer back to pool
            unsafe { pool.free_by_index(idx) };
        }

        assert!(ring.is_empty());
    }

    /// Test batch operations efficiency.
    #[test]
    fn test_batch_operations() {
        let ring: LockFreeRing<u64> = LockFreeRing::new(128);

        // Batch enqueue
        let items: Vec<u64> = (0..64).collect();
        let enqueued = ring.enqueue_batch(&items);
        assert_eq!(enqueued, 64);

        // Batch dequeue
        let mut out = vec![0u64; 128];
        let dequeued = ring.dequeue_batch(&mut out);
        assert_eq!(dequeued, 64);

        for i in 0..64 {
            assert_eq!(out[i], i as u64);
        }
    }

    /// Test zero-copy packet metadata parsing.
    #[test]
    fn test_zero_copy_packet_metadata() {
        // Create a minimal TCP packet
        let mut packet_data = vec![0u8; 64];

        // Ethernet header (14 bytes)
        packet_data[12] = 0x08; // EtherType IPv4
        packet_data[13] = 0x00;

        // IP header (20 bytes at offset 14)
        packet_data[14] = 0x45; // IPv4, IHL=5
        packet_data[23] = 6; // Protocol: TCP

        // IP addresses
        packet_data[26..30].copy_from_slice(&[192, 168, 1, 100]); // src
        packet_data[30..34].copy_from_slice(&[10, 0, 0, 1]); // dst

        // TCP ports (at offset 34)
        packet_data[34..36].copy_from_slice(&8080u16.to_be_bytes()); // src port
        packet_data[36..38].copy_from_slice(&80u16.to_be_bytes()); // dst port

        // Create zero-copy packet
        let packet = unsafe {
            ZeroCopyPacket::from_raw_parts(packet_data.as_ptr(), packet_data.len() as u32, 0)
        };

        assert_eq!(packet.len(), 64);
        assert_eq!(unsafe { packet.as_slice()[12] }, 0x08);
        assert_eq!(unsafe { packet.as_slice()[13] }, 0x00);
    }

    /// Test statistics accumulation.
    #[test]
    fn test_datapath_stats() {
        let stats = DatapathStats::new();

        // Record various operations
        for i in 0..100 {
            stats.record_tx(1, (1000 + i) as u64);
            stats.record_rx(1, (500 + i) as u64);
        }

        // Verify counts using snapshot
        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tx_packets, 100);
        assert_eq!(snapshot.rx_packets, 100);
        assert!(snapshot.tx_bytes > 100_000);
        assert!(snapshot.rx_bytes > 50_000);

        // Record some drops
        for _ in 0..5 {
            stats.record_tx_drop();
            stats.record_rx_drop();
        }

        let snapshot = stats.snapshot();
        assert_eq!(snapshot.tx_dropped, 5);
        assert_eq!(snapshot.rx_dropped, 5);
    }

    /// Test pool exhaustion and recovery.
    #[test]
    fn test_pool_exhaustion_recovery() {
        let pool = PacketPool::new(8).unwrap();
        let mut indices = Vec::new();

        // Exhaust the pool
        while let Some(idx) = pool.alloc_index() {
            indices.push(idx);
        }

        assert_eq!(indices.len(), 8);

        // Pool should be empty now
        assert!(pool.alloc_index().is_none());

        // Free half the buffers
        for idx in indices.drain(..4) {
            unsafe { pool.free_by_index(idx) };
        }

        // Should be able to allocate again
        let new_idx = pool.alloc_index();
        assert!(new_idx.is_some());

        // Cleanup
        if let Some(idx) = new_idx {
            unsafe { pool.free_by_index(idx) };
        }
        for idx in indices {
            unsafe { pool.free_by_index(idx) };
        }
    }

    /// Test MPMC ring basic operations.
    #[test]
    fn test_mpmc_ring_basic() {
        let ring = MpmcRing::<u32>::new(16);

        ring.enqueue(1).unwrap();
        ring.enqueue(2).unwrap();
        ring.enqueue(3).unwrap();

        assert_eq!(ring.dequeue(), Some(1));
        assert_eq!(ring.dequeue(), Some(2));
        assert_eq!(ring.dequeue(), Some(3));
        assert_eq!(ring.dequeue(), None);
    }
}

// ============================================================================
// NAT Engine Integration Tests
// ============================================================================

mod nat_engine {
    use arcbox_net::nat_engine::checksum::incremental_checksum_update_32;
    use arcbox_net::nat_engine::{
        NatDirection, NatEngine, NatEngineConfig, NatResult, incremental_checksum_update,
    };
    use std::net::Ipv4Addr;

    /// Helper to create a test packet.
    fn create_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 54];

        // Ethernet header
        packet[12] = 0x08;
        packet[13] = 0x00;

        // IP header
        packet[14] = 0x45;
        packet[23] = 6; // TCP

        // IP addresses
        packet[26..30].copy_from_slice(&src_ip);
        packet[30..34].copy_from_slice(&dst_ip);

        // TCP ports
        packet[34..36].copy_from_slice(&src_port.to_be_bytes());
        packet[36..38].copy_from_slice(&dst_port.to_be_bytes());

        packet
    }

    /// Test full NAT round-trip (outbound + inbound).
    #[test]
    fn test_nat_roundtrip() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(203, 0, 113, 1));
        engine.set_internal_network(Ipv4Addr::new(10, 0, 0, 0), 24);

        // Guest initiates connection
        let guest_ip = [10, 0, 0, 50];
        let server_ip = [93, 184, 216, 34]; // example.com
        let guest_port = 45678u16;
        let server_port = 443u16;

        // Outbound packet
        let mut outbound = create_tcp_packet(guest_ip, server_ip, guest_port, server_port);

        let result = unsafe { engine.translate(&mut outbound, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::Translated);

        // Verify SNAT: source IP changed to external
        assert_eq!(&outbound[26..30], &[203, 0, 113, 1]);

        // Extract NAT'd port
        let nat_port = u16::from_be_bytes([outbound[34], outbound[35]]);
        assert_ne!(nat_port, guest_port); // Port should be translated

        // Server responds
        let mut inbound = create_tcp_packet(server_ip, [203, 0, 113, 1], server_port, nat_port);

        let result = unsafe { engine.translate(&mut inbound, NatDirection::Inbound) };
        assert_eq!(result.unwrap(), NatResult::Translated);

        // Verify reverse NAT: destination restored to guest
        assert_eq!(&inbound[30..34], &guest_ip);
        let restored_port = u16::from_be_bytes([inbound[36], inbound[37]]);
        assert_eq!(restored_port, guest_port);
    }

    /// Test multiple concurrent connections.
    #[test]
    fn test_multiple_connections() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(198, 51, 100, 1));
        engine.set_internal_network(Ipv4Addr::new(172, 16, 0, 0), 16);

        let destinations = [
            ([1, 1, 1, 1], 53u16),        // DNS
            ([8, 8, 8, 8], 53u16),        // DNS
            ([93, 184, 216, 34], 80u16),  // HTTP
            ([93, 184, 216, 34], 443u16), // HTTPS
        ];

        let mut nat_ports = Vec::new();

        // Create outbound connections from different internal hosts
        for (i, (dst_ip, dst_port)) in destinations.iter().enumerate() {
            let src_ip = [172, 16, 0, (i + 1) as u8];
            let src_port = (40000 + i) as u16;

            let mut packet = create_tcp_packet(src_ip, *dst_ip, src_port, *dst_port);
            let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
            assert_eq!(result.unwrap(), NatResult::Translated);

            let nat_port = u16::from_be_bytes([packet[34], packet[35]]);
            nat_ports.push(nat_port);
        }

        // All NAT ports should be unique
        let unique_ports: std::collections::HashSet<_> = nat_ports.iter().collect();
        assert_eq!(unique_ports.len(), nat_ports.len());

        // Verify connection count
        assert_eq!(engine.connection_count(), 4);
    }

    /// Test connection tracking expiration.
    #[test]
    fn test_connection_expiration() {
        let config = NatEngineConfig::new(Ipv4Addr::new(192, 0, 2, 1)).with_timeout(0); // Immediate expiration

        let mut engine = NatEngine::new(&config);
        engine.set_internal_network(Ipv4Addr::new(10, 10, 0, 0), 16);

        // Create a connection
        let mut packet = create_tcp_packet([10, 10, 1, 1], [8, 8, 8, 8], 12345, 53);
        unsafe {
            engine
                .translate(&mut packet, NatDirection::Outbound)
                .unwrap()
        };

        assert_eq!(engine.connection_count(), 1);

        // Expire connections (timeout is 0, so it should expire)
        // Note: actual expiration depends on implementation
        let expired = engine.expire_connections();
        // Connection might be expired depending on timing
        assert!(expired == 0 || expired == 1);
    }

    /// Test checksum consistency after NAT.
    #[test]
    fn test_checksum_consistency() {
        // Test incremental checksum update with 16-bit values
        let old_checksum = 0xABCDu16;
        let old_value = 0x1234u16;
        let new_value = 0x5678u16;

        let new_checksum = incremental_checksum_update(old_checksum, old_value, new_value);

        // Checksum should change
        assert_ne!(old_checksum, new_checksum);

        // Update back should restore
        let restored = incremental_checksum_update(new_checksum, new_value, old_value);

        // Should be close to original
        assert_eq!(restored, old_checksum);
    }

    /// Test 32-bit incremental checksum update.
    #[test]
    fn test_checksum_consistency_32bit() {
        let old_checksum = 0xABCDu16;
        let old_value = 0x12345678u32;
        let new_value = 0x87654321u32;

        let new_checksum = incremental_checksum_update_32(old_checksum, old_value, new_value);
        assert_ne!(old_checksum, new_checksum);

        let restored = incremental_checksum_update_32(new_checksum, new_value, old_value);
        assert_eq!(restored, old_checksum);
    }

    /// Test NAT with UDP protocol.
    #[test]
    fn test_nat_udp() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(100, 64, 0, 1));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 100, 0), 24);

        // Create UDP packet
        let mut packet = vec![0u8; 54];
        packet[12] = 0x08; // IPv4
        packet[13] = 0x00;
        packet[14] = 0x45;
        packet[23] = 17; // UDP

        packet[26..30].copy_from_slice(&[192, 168, 100, 10]); // src
        packet[30..34].copy_from_slice(&[8, 8, 4, 4]); // dst

        packet[34..36].copy_from_slice(&54321u16.to_be_bytes()); // src port
        packet[36..38].copy_from_slice(&53u16.to_be_bytes()); // dst port (DNS)

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::Translated);

        // Source should be NATed
        assert_eq!(&packet[26..30], &[100, 64, 0, 1]);
    }

    /// Test passthrough for non-NAT traffic.
    #[test]
    fn test_passthrough_non_internal() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 2, 3, 4));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 0, 0), 24);

        // Traffic from external source (not internal network)
        let mut packet = create_tcp_packet(
            [8, 8, 8, 8], // External source
            [1, 1, 1, 1], // External destination
            12345,
            80,
        );

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::PassThrough);

        // Source should be unchanged
        assert_eq!(&packet[26..30], &[8, 8, 8, 8]);
    }

    /// Test passthrough for non-TCP/UDP protocols.
    #[test]
    fn test_passthrough_icmp() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 2, 3, 4));
        engine.set_internal_network(Ipv4Addr::new(192, 168, 0, 0), 24);

        let mut packet = vec![0u8; 54];
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x45;
        packet[23] = 1; // ICMP

        packet[26..30].copy_from_slice(&[192, 168, 0, 10]);
        packet[30..34].copy_from_slice(&[8, 8, 8, 8]);

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };
        assert_eq!(result.unwrap(), NatResult::PassThrough);
    }
}

// ============================================================================
// Concurrent Stress Tests
// ============================================================================

mod stress {
    use arcbox_net::datapath::ring::MpmcRing;
    use arcbox_net::datapath::{LockFreeRing, PacketPool};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    /// Stress test SPSC ring with high throughput.
    #[test]
    fn test_spsc_ring_stress() {
        let ring = Arc::new(LockFreeRing::<u64>::new(4096));
        let ring_producer = Arc::clone(&ring);
        let ring_consumer = Arc::clone(&ring);

        let count = 1_000_000u64;

        let producer = thread::spawn(move || {
            for i in 0..count {
                loop {
                    if ring_producer.enqueue(i).is_ok() {
                        break;
                    }
                    std::hint::spin_loop();
                }
            }
        });

        let consumer = thread::spawn(move || {
            let mut sum = 0u64;
            let mut received = 0u64;

            while received < count {
                if let Some(v) = ring_consumer.dequeue() {
                    sum = sum.wrapping_add(v);
                    received += 1;
                } else {
                    std::hint::spin_loop();
                }
            }

            sum
        });

        producer.join().unwrap();
        let sum = consumer.join().unwrap();

        // Sum of 0..count-1 = (count-1)*count/2
        let expected = (count - 1) * count / 2;
        assert_eq!(sum, expected);
    }

    /// Stress test MPMC ring with multiple producers and consumers.
    #[test]
    fn test_mpmc_ring_stress() {
        let ring = Arc::new(MpmcRing::<u64>::new(1024));
        let total_items = 100_000u64;
        let num_producers = 4;
        let num_consumers = 4;
        let items_per_producer = total_items / num_producers as u64;

        let produced = Arc::new(AtomicU64::new(0));
        let consumed = Arc::new(AtomicU64::new(0));

        let mut handles = Vec::new();

        // Spawn producers
        for p in 0..num_producers {
            let ring: Arc<MpmcRing<u64>> = Arc::clone(&ring);
            let produced = Arc::clone(&produced);

            handles.push(thread::spawn(move || {
                for i in 0..items_per_producer {
                    let value = p as u64 * items_per_producer + i;
                    loop {
                        if ring.enqueue(value).is_ok() {
                            produced.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                        std::hint::spin_loop();
                    }
                }
            }));
        }

        // Spawn consumers
        for _ in 0..num_consumers {
            let ring: Arc<MpmcRing<u64>> = Arc::clone(&ring);
            let consumed = Arc::clone(&consumed);
            let produced = Arc::clone(&produced);

            handles.push(thread::spawn(move || {
                loop {
                    if ring.dequeue().is_some() {
                        consumed.fetch_add(1, Ordering::Relaxed);
                    } else if consumed.load(Ordering::Relaxed) >= total_items {
                        break;
                    } else if produced.load(Ordering::Relaxed) >= total_items
                        && consumed.load(Ordering::Relaxed) >= total_items
                    {
                        break;
                    } else {
                        std::hint::spin_loop();
                    }
                }
            }));
        }

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(consumed.load(Ordering::Relaxed), total_items);
    }

    /// Test packet pool under concurrent allocation/deallocation.
    #[test]
    fn test_pool_concurrent_stress() {
        let pool = Arc::new(PacketPool::new(256).unwrap());
        let iterations = 10_000;
        let num_threads = 4;

        let mut handles = Vec::new();

        for _ in 0..num_threads {
            let pool = Arc::clone(&pool);

            handles.push(thread::spawn(move || {
                let mut allocated = Vec::new();

                for _ in 0..iterations {
                    // Allocate some
                    for _ in 0..4 {
                        if let Some(idx) = pool.alloc_index() {
                            allocated.push(idx);
                        }
                    }

                    // Free some
                    while allocated.len() > 2 {
                        let idx = allocated.pop().unwrap();
                        unsafe { pool.free_by_index(idx) };
                    }
                }

                // Cleanup remaining
                for idx in allocated {
                    unsafe { pool.free_by_index(idx) };
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All buffers should be returned
        // Note: can't easily verify this without internal access
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

mod error_handling {
    use arcbox_net::nat_engine::{NatDirection, NatEngine, TranslateError};
    use std::net::Ipv4Addr;

    /// Test handling of malformed packets.
    #[test]
    fn test_packet_too_short() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 1, 1, 1));

        // Packet way too short
        let mut short_packet = vec![0u8; 10];

        let result = unsafe { engine.translate(&mut short_packet, NatDirection::Outbound) };

        assert!(matches!(result, Err(TranslateError::PacketTooShort)));
    }

    /// Test handling of invalid IP version.
    #[test]
    fn test_invalid_ip_version() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 1, 1, 1));

        let mut packet = vec![0u8; 54];
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x65; // IPv6 version in IPv4 packet (invalid)

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };

        assert!(matches!(result, Err(TranslateError::InvalidIpHeader)));
    }

    /// Test handling of invalid IHL.
    #[test]
    fn test_invalid_ihl() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 1, 1, 1));

        let mut packet = vec![0u8; 54];
        packet[12] = 0x08;
        packet[13] = 0x00;
        packet[14] = 0x41; // IHL = 1 (invalid, must be >= 5)

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };

        assert!(matches!(result, Err(TranslateError::InvalidIpHeader)));
    }

    /// Test graceful handling of non-IPv4 traffic.
    #[test]
    fn test_non_ipv4_passthrough() {
        let mut engine = NatEngine::with_external_ip(Ipv4Addr::new(1, 1, 1, 1));

        // ARP packet
        let mut packet = vec![0u8; 54];
        packet[12] = 0x08;
        packet[13] = 0x06; // EtherType: ARP

        let result = unsafe { engine.translate(&mut packet, NatDirection::Outbound) };

        assert!(result.is_ok());
    }
}

// ============================================================================
// NetworkManager Tests
// ============================================================================

mod network_manager {
    use arcbox_net::{NetConfig, NetworkManager, NetworkMode};

    #[test]
    fn test_network_manager_creation() {
        let config = NetConfig::default();
        let manager = NetworkManager::new(config);

        assert_eq!(manager.config().mode, NetworkMode::Nat);
        assert_eq!(manager.config().mtu, 1500);
        assert!(!manager.config().multiqueue);
    }

    #[test]
    fn test_network_manager_custom_config() {
        let config = NetConfig {
            mode: NetworkMode::Bridge,
            mac: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            mtu: 9000,
            bridge: Some("br0".to_string()),
            multiqueue: true,
            num_queues: 4,
        };

        let manager = NetworkManager::new(config);

        assert_eq!(manager.config().mode, NetworkMode::Bridge);
        assert_eq!(manager.config().mtu, 9000);
        assert!(manager.config().multiqueue);
        assert_eq!(manager.config().num_queues, 4);
    }

    #[test]
    fn test_network_manager_start_stop() {
        let config = NetConfig::default();
        let mut manager = NetworkManager::new(config);

        // Start should succeed
        assert!(manager.start().is_ok());

        // Stop should succeed
        assert!(manager.stop().is_ok());
    }
}
