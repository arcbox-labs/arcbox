//! Integration tests for Darwin dirty page tracking.
//!
//! These tests verify the software-based dirty page tracking implementation
//! for macOS Virtualization.framework, which uses FNV-1a checksums to detect
//! modified pages.
//!
//! Note: Darwin doesn't have hardware dirty page tracking like KVM, so we
//! implement a software-based solution using page checksums.

#![cfg(target_os = "macos")]
#![allow(clippy::expect_fun_call)]
#![allow(clippy::field_reassign_with_default)]

use std::time::Instant;

use arcbox_hypervisor::{
    darwin::{is_supported, DarwinMemory},
    memory::{GuestAddress, PAGE_SIZE},
    traits::GuestMemory,
};

// ============================================================================
// Dirty Tracking Enable/Disable Tests
// ============================================================================

/// Test enabling dirty page tracking.
///
/// Verifies that:
/// 1. Dirty tracking can be enabled without error
/// 2. Enabling twice is idempotent (no error)
#[test]
fn test_enable_dirty_tracking() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    // Create 64KB memory (16 pages of 4KB each)
    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    // Enable dirty tracking
    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Enable again - should be idempotent
    memory
        .enable_dirty_tracking()
        .expect("Second enable should succeed");

    println!("Dirty tracking enabled successfully (idempotent)");
}

/// Test disabling dirty page tracking.
///
/// Verifies that:
/// 1. Dirty tracking can be disabled without error
/// 2. Disabling frees the checksum memory
#[test]
fn test_disable_dirty_tracking() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    // Enable then disable
    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    memory
        .disable_dirty_tracking()
        .expect("Failed to disable dirty tracking");

    // After disabling, get_dirty_pages should fail
    let result = memory.get_dirty_pages();
    assert!(
        result.is_err(),
        "get_dirty_pages should fail when tracking is disabled"
    );

    println!("Dirty tracking disabled successfully");
}

// ============================================================================
// Dirty Page Detection Tests
// ============================================================================

/// Test that get_dirty_pages returns empty when no pages have been modified.
///
/// Verifies that immediately after enabling tracking, no pages are reported
/// as dirty since no writes have occurred.
#[test]
fn test_get_dirty_pages_empty() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Get dirty pages immediately - should be empty
    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");

    assert!(
        dirty.is_empty(),
        "Expected no dirty pages immediately after enable, got {}",
        dirty.len()
    );

    // Call again - still empty
    let dirty2 = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert!(
        dirty2.is_empty(),
        "Expected no dirty pages on second call, got {}",
        dirty2.len()
    );

    println!("Empty dirty page detection works correctly");
}

/// Test that dirty pages are detected after writes.
///
/// Verifies that:
/// 1. Writing to memory marks pages as dirty
/// 2. The correct pages are reported as dirty
/// 3. After calling get_dirty_pages, the dirty list is cleared
#[test]
fn test_get_dirty_pages_after_write() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    // Enable tracking
    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Write to page 1 (offset 0x1000 = 4096, which is the start of page 1)
    let data = [0xAA_u8; 256];
    memory
        .write(GuestAddress::new(0x1000), &data)
        .expect("Failed to write to memory");

    // Get dirty pages
    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");

    assert!(
        !dirty.is_empty(),
        "Expected dirty pages after write, got none"
    );

    // Page 1 should be dirty (address 0x1000 is in page 1)
    let page1_addr = 0x1000_u64; // Page 1 starts at 0x1000
    let found = dirty.iter().any(|p| p.guest_addr == page1_addr);
    assert!(found, "Page 1 (0x1000) should be dirty, got: {:?}", dirty);

    // Verify page size
    for page in &dirty {
        assert_eq!(
            page.size, PAGE_SIZE,
            "Dirty page should have size {}",
            PAGE_SIZE
        );
    }

    // Get dirty pages again - should be empty now (cleared after previous call)
    let dirty2 = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert!(
        dirty2.is_empty(),
        "Expected no dirty pages after clearing, got {}",
        dirty2.len()
    );

    println!("Dirty page detection after write works correctly");
}

/// Test that multiple dirty pages are detected.
#[test]
fn test_multiple_dirty_pages() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Write to multiple pages
    let data = [0xBB_u8; 128];

    // Page 0 (offset 0)
    memory
        .write(GuestAddress::new(0), &data)
        .expect("Failed to write to page 0");

    // Page 2 (offset 0x2000)
    memory
        .write(GuestAddress::new(0x2000), &data)
        .expect("Failed to write to page 2");

    // Page 5 (offset 0x5000)
    memory
        .write(GuestAddress::new(0x5000), &data)
        .expect("Failed to write to page 5");

    // Get dirty pages
    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");

    assert_eq!(
        dirty.len(),
        3,
        "Expected 3 dirty pages, got {}",
        dirty.len()
    );

    // Verify specific pages are dirty
    let dirty_addrs: Vec<u64> = dirty.iter().map(|p| p.guest_addr).collect();
    assert!(dirty_addrs.contains(&0), "Page 0 should be dirty");
    assert!(dirty_addrs.contains(&0x2000), "Page 2 should be dirty");
    assert!(dirty_addrs.contains(&0x5000), "Page 5 should be dirty");

    println!(
        "Multiple dirty page detection works correctly: {:?}",
        dirty_addrs
    );
}

/// Test that writes spanning page boundaries dirty both pages.
#[test]
fn test_cross_page_write() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Write across page boundary (end of page 0 into page 1)
    // Page 0 ends at 0xFFF, page 1 starts at 0x1000
    let data = [0xCC_u8; 256]; // 256 bytes
    let write_addr = PAGE_SIZE - 128; // Start 128 bytes before page boundary
    memory
        .write(GuestAddress::new(write_addr), &data)
        .expect("Failed to write across page boundary");

    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");

    // Both page 0 and page 1 should be dirty
    assert!(
        dirty.len() >= 2,
        "Expected at least 2 dirty pages for cross-boundary write, got {}",
        dirty.len()
    );

    let dirty_addrs: Vec<u64> = dirty.iter().map(|p| p.guest_addr).collect();
    assert!(
        dirty_addrs.contains(&0),
        "Page 0 should be dirty for cross-boundary write"
    );
    assert!(
        dirty_addrs.contains(&PAGE_SIZE),
        "Page 1 should be dirty for cross-boundary write"
    );

    println!("Cross-page boundary write detection works correctly");
}

// ============================================================================
// Performance Tests
// ============================================================================

/// Test dirty page tracking performance (FNV-1a hash overhead).
///
/// This test measures the overhead of the software-based dirty tracking
/// using checksums. The FNV-1a algorithm is chosen for its simplicity
/// and reasonable performance.
///
/// Note: This test is marked #[ignore] because it takes longer to run.
#[test]
#[ignore]
fn test_dirty_tracking_performance() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    // Test with different memory sizes
    let test_sizes = [
        (1 * 1024 * 1024, "1MB"),   // 256 pages
        (16 * 1024 * 1024, "16MB"), // 4096 pages
        (64 * 1024 * 1024, "64MB"), // 16384 pages
    ];

    println!("\nDirty tracking performance (FNV-1a checksum):");
    println!("{:>10} {:>12} {:>12} {:>15}", "Size", "Enable (ms)", "Check (ms)", "Pages/ms");
    println!("{}", "-".repeat(55));

    for (size, label) in test_sizes {
        let mut memory = DarwinMemory::new(size).expect("Failed to create memory");
        let num_pages = size / PAGE_SIZE as u64;

        // Measure enable_dirty_tracking time (computes all checksums)
        let start = Instant::now();
        memory
            .enable_dirty_tracking()
            .expect("Failed to enable dirty tracking");
        let enable_time = start.elapsed();

        // Measure get_dirty_pages time (recomputes and compares checksums)
        let start = Instant::now();
        let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
        let check_time = start.elapsed();

        // Should be empty since nothing was written
        assert!(
            dirty.is_empty(),
            "Expected no dirty pages for clean memory"
        );

        let enable_ms = enable_time.as_secs_f64() * 1000.0;
        let check_ms = check_time.as_secs_f64() * 1000.0;
        let pages_per_ms = num_pages as f64 / check_ms;

        println!(
            "{:>10} {:>12.2} {:>12.2} {:>15.0}",
            label, enable_ms, check_ms, pages_per_ms
        );

        memory
            .disable_dirty_tracking()
            .expect("Failed to disable dirty tracking");
    }

    println!();
    println!("Performance test completed");
}

/// Test dirty tracking performance with dirty pages.
///
/// Measures the impact of having actual dirty pages on the tracking
/// performance.
#[test]
#[ignore]
fn test_dirty_tracking_performance_with_writes() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let size = 16 * 1024 * 1024_u64; // 16MB
    let mut memory = DarwinMemory::new(size).expect("Failed to create memory");
    let num_pages = size / PAGE_SIZE;

    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    println!("\nDirty tracking with writes (16MB memory, {} pages):", num_pages);
    println!("{:>15} {:>12} {:>15}", "Dirty pages", "Check (ms)", "Pages/ms");
    println!("{}", "-".repeat(45));

    // Test with different amounts of dirty pages
    let dirty_counts = [0, 10, 100, 1000, 4096];

    for &dirty_count in &dirty_counts {
        // Reset by getting dirty pages
        let _ = memory.get_dirty_pages();

        // Write to specified number of pages
        let data = [0xFF_u8; 64];
        for i in 0..dirty_count {
            let page_idx = (i * 4) % (num_pages as usize); // Spread writes across memory
            let addr = (page_idx as u64) * PAGE_SIZE;
            memory
                .write(GuestAddress::new(addr), &data)
                .expect("Failed to write");
        }

        // Measure get_dirty_pages time
        let start = Instant::now();
        let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
        let check_time = start.elapsed();

        let check_ms = check_time.as_secs_f64() * 1000.0;
        let pages_per_ms = num_pages as f64 / check_ms;

        println!(
            "{:>15} {:>12.2} {:>15.0}",
            dirty.len(),
            check_ms,
            pages_per_ms
        );
    }

    println!();
    println!("Performance test with writes completed");
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test dirty tracking with minimum memory size (single page).
#[test]
fn test_dirty_tracking_single_page() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(PAGE_SIZE).expect("Failed to create single page memory");

    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // No changes - should be empty
    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert!(dirty.is_empty(), "Expected no dirty pages initially");

    // Write to the single page
    let data = [0xDD_u8; 16];
    memory
        .write(GuestAddress::new(0), &data)
        .expect("Failed to write");

    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert_eq!(dirty.len(), 1, "Expected exactly 1 dirty page");
    assert_eq!(dirty[0].guest_addr, 0, "Dirty page should be at address 0");

    println!("Single page dirty tracking works correctly");
}

/// Test that same data written twice doesn't re-dirty the page.
#[test]
fn test_same_data_not_dirty() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    // Write initial data
    let data = [0xEE_u8; 256];
    memory
        .write(GuestAddress::new(0x1000), &data)
        .expect("Failed to write initial data");

    // Enable tracking after initial write
    memory
        .enable_dirty_tracking()
        .expect("Failed to enable dirty tracking");

    // Write the same data again
    memory
        .write(GuestAddress::new(0x1000), &data)
        .expect("Failed to write same data");

    // The page should NOT be dirty since the content is identical
    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert!(
        dirty.is_empty(),
        "Page should not be dirty when writing identical data, got {} dirty pages",
        dirty.len()
    );

    // Write different data
    let new_data = [0xFF_u8; 256];
    memory
        .write(GuestAddress::new(0x1000), &new_data)
        .expect("Failed to write new data");

    let dirty = memory.get_dirty_pages().expect("Failed to get dirty pages");
    assert_eq!(
        dirty.len(),
        1,
        "Page should be dirty after writing different data"
    );

    println!("Same-data-not-dirty optimization works correctly");
}

/// Test error handling when dirty tracking is not enabled.
#[test]
fn test_get_dirty_pages_without_enable() {
    if !is_supported() {
        println!("Virtualization not supported, skipping");
        return;
    }

    let mut memory = DarwinMemory::new(64 * 1024).expect("Failed to create memory");

    // Should fail without enabling
    let result = memory.get_dirty_pages();
    assert!(
        result.is_err(),
        "get_dirty_pages should fail when tracking not enabled"
    );

    println!("Error handling for disabled tracking works correctly");
}
