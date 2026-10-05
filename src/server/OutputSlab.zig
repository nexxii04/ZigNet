const std = @import("std");

/// Pool of datagram-sized slots for the output path. A slot is serialized
/// and sent in place, so the retransmission backup needs no heap or copy.
pub const OutputSlab = struct {
    memory: []align(64) u8,
    free_slots: []u32,
    free_len: usize,
    slot_size: usize,
    /// Owners per slot; the slot returns to the pool at zero.
    slot_refs: []u32,
    locked: std.atomic.Value(bool) = .init(false),

    pub fn init(allocator: std.mem.Allocator, slot_count: usize, slot_size: usize) !OutputSlab {
        const memory = try allocator.alignedAlloc(u8, .@"64", slot_count * slot_size);
        errdefer allocator.free(memory);
        const free_slots = try allocator.alloc(u32, slot_count);
        errdefer allocator.free(free_slots);
        const slot_refs = try allocator.alloc(u32, slot_count);
        @memset(slot_refs, 0);
        for (free_slots, 0..) |*slot, index| slot.* = @intCast(index);
        return .{
            .memory = memory,
            .free_slots = free_slots,
            .free_len = slot_count,
            .slot_size = slot_size,
            .slot_refs = slot_refs,
        };
    }

    pub fn deinit(self: *OutputSlab, allocator: std.mem.Allocator) void {
        allocator.free(self.memory);
        allocator.free(self.free_slots);
        allocator.free(self.slot_refs);
    }

    fn lock(self: *OutputSlab) void {
        while (self.locked.swap(true, .acquire)) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *OutputSlab) void {
        self.locked.store(false, .release);
    }

    pub fn capacity(self: *const OutputSlab) usize {
        return self.free_slots.len;
    }

    pub fn available(self: *OutputSlab) usize {
        self.lock();
        defer self.unlock();
        return self.free_len;
    }

    pub fn claim(self: *OutputSlab) ?u32 {
        self.lock();
        defer self.unlock();
        if (self.free_len == 0) return null;
        self.free_len -= 1;
        const slot = self.free_slots[self.free_len];
        std.debug.assert(self.slot_refs[slot] == 0);
        self.slot_refs[slot] = 1;
        return slot;
    }

    pub fn retain(self: *OutputSlab, slot: u32) void {
        self.lock();
        defer self.unlock();
        std.debug.assert(self.slot_refs[slot] > 0);
        std.debug.assert(self.slot_refs[slot] < std.math.maxInt(u32));
        self.slot_refs[slot] += 1;
    }

    pub fn release(self: *OutputSlab, slot: u32) void {
        self.lock();
        defer self.unlock();
        std.debug.assert(self.slot_refs[slot] > 0);
        self.slot_refs[slot] -= 1;
        if (self.slot_refs[slot] != 0) return;
        std.debug.assert(self.free_len < self.free_slots.len);
        self.free_slots[self.free_len] = slot;
        self.free_len += 1;
    }

    pub fn slotBytes(self: *const OutputSlab, slot: u32) []u8 {
        const start = @as(usize, slot) * self.slot_size;
        return self.memory[start..][0..self.slot_size];
    }
};

test "the slab hands out every slot once and takes them back" {
    const allocator = std.testing.allocator;
    var slab = try OutputSlab.init(allocator, 4, 64);
    defer slab.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), slab.capacity());
    try std.testing.expectEqual(@as(usize, 4), slab.available());

    var claimed: [4]u32 = undefined;
    for (&claimed) |*slot| slot.* = slab.claim() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), slab.available());
    try std.testing.expect(slab.claim() == null);

    for (claimed, 0..) |slot, i| {
        for (claimed[i + 1 ..]) |other| try std.testing.expect(slot != other);
    }
    const first = slab.slotBytes(claimed[0]);
    const second = slab.slotBytes(claimed[1]);
    try std.testing.expect(@intFromPtr(first.ptr) + first.len <= @intFromPtr(second.ptr) or
        @intFromPtr(second.ptr) + second.len <= @intFromPtr(first.ptr));

    slab.release(claimed[2]);
    try std.testing.expectEqual(@as(usize, 1), slab.available());
    try std.testing.expectEqual(claimed[2], slab.claim().?);
}

test "a retained slot only returns to the pool with the last reference" {
    const allocator = std.testing.allocator;
    var slab = try OutputSlab.init(allocator, 2, 32);
    defer slab.deinit(allocator);

    const slot = slab.claim() orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), slab.available());

    slab.retain(slot);
    slab.release(slot);
    try std.testing.expectEqual(@as(usize, 1), slab.available());

    const other = slab.claim() orelse return error.TestUnexpectedResult;
    try std.testing.expect(other != slot);
    try std.testing.expect(slab.claim() == null);
    slab.release(other);

    slab.release(slot);
    try std.testing.expectEqual(@as(usize, 2), slab.available());
    try std.testing.expectEqual(slot, slab.claim().?);
}
