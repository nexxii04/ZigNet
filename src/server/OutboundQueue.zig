const std = @import("std");

/// One datagram handed to the outbound sender thread. `bytes` must stay
/// valid until the sender releases it.
pub const Datagram = struct {
    to: std.Io.net.IpAddress,
    bytes: []const u8,
    release: Release = .none,

    pub const Release = union(enum) {
        /// Not pooled; the caller keeps the storage alive.
        none,
        /// Output slab slot; the queue holds a reference while in flight.
        slab_slot: u32,
        /// Transient pool slot, freed right after the send.
        transient_slot: u32,
    };
};

/// Bounded lock-free MPSC ring (Vyukov queue). A single FIFO consumer keeps
/// per-connection order. `enqueue` returns false when full instead of
/// blocking, so the caller can fall back to a direct send.
pub const OutboundQueue = struct {
    const Cell = struct {
        sequence: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        data: Datagram = undefined,
    };

    buffer: []Cell,
    mask: usize,
    head: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    tail: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

    pub fn init(allocator: std.mem.Allocator, requested_capacity: usize) !OutboundQueue {
        const size = std.math.ceilPowerOfTwo(usize, @max(requested_capacity, 2)) catch return error.OutOfMemory;
        const buffer = try allocator.alloc(Cell, size);
        for (buffer, 0..) |*cell, index| {
            cell.* = .{ .sequence = std.atomic.Value(usize).init(index) };
        }
        return .{ .buffer = buffer, .mask = size - 1 };
    }

    pub fn deinit(self: *OutboundQueue, allocator: std.mem.Allocator) void {
        allocator.free(self.buffer);
        self.buffer = &.{};
    }

    pub fn capacity(self: *const OutboundQueue) usize {
        return self.buffer.len;
    }

    /// Returns false when full; the datagram stays owned by the caller.
    pub fn enqueue(self: *OutboundQueue, datagram: Datagram) bool {
        var pos = self.tail.load(.acquire);
        while (true) {
            const cell = &self.buffer[pos & self.mask];
            const sequence = cell.sequence.load(.acquire);
            const diff: isize = @bitCast(sequence -% pos);
            if (diff == 0) {
                if (self.tail.cmpxchgWeak(pos, pos + 1, .acq_rel, .acquire)) |actual| {
                    pos = actual;
                    continue;
                }
                cell.data = datagram;
                cell.sequence.store(pos + 1, .release);
                return true;
            }
            if (diff < 0) return false;
            pos = self.tail.load(.acquire);
        }
    }

    pub fn dequeue(self: *OutboundQueue) ?Datagram {
        const pos = self.head.load(.acquire);
        const cell = &self.buffer[pos & self.mask];
        const sequence = cell.sequence.load(.acquire);
        const diff: isize = @bitCast(sequence -% (pos + 1));
        if (diff != 0) return null;
        const datagram = cell.data;
        cell.sequence.store(pos +% self.buffer.len, .release);
        self.head.store(pos + 1, .release);
        return datagram;
    }

    /// Approximate; safe from any thread.
    pub fn depth(self: *const OutboundQueue) usize {
        const tail = self.tail.load(.monotonic);
        const head = self.head.load(.monotonic);
        return tail -% head;
    }
};

test "the outbound ring is FIFO, wraps and reports fullness" {
    const allocator = std.testing.allocator;
    var queue = try OutboundQueue.init(allocator, 4);
    defer queue.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 4), queue.capacity());
    try std.testing.expect(queue.dequeue() == null);
    try std.testing.expectEqual(@as(usize, 0), queue.depth());

    const addr: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19132 } };
    var payloads = [_][1]u8{.{0}} ** 4;
    for (0..4) |i| {
        payloads[i][0] = @intCast(i);
        try std.testing.expect(queue.enqueue(.{ .to = addr, .bytes = &payloads[i] }));
    }
    try std.testing.expectEqual(@as(usize, 4), queue.depth());

    try std.testing.expect(!queue.enqueue(.{ .to = addr, .bytes = "x" }));

    for (0..4) |i| {
        const datagram = queue.dequeue() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u8, @intCast(i)), datagram.bytes[0]);
    }
    try std.testing.expect(queue.dequeue() == null);

    for (0..4) |i| {
        payloads[i][0] = @intCast(10 + i);
        try std.testing.expect(queue.enqueue(.{ .to = addr, .bytes = &payloads[i] }));
    }
    for (0..4) |i| {
        const datagram = queue.dequeue() orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(u8, @intCast(10 + i)), datagram.bytes[0]);
    }
}

test "the outbound ring preserves per-producer order across threads" {
    const allocator = std.testing.allocator;
    var queue = try OutboundQueue.init(allocator, 64);
    defer queue.deinit(allocator);

    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19132 } };
    const total_per_producer: usize = 400;

    const Producer = struct {
        queue: *OutboundQueue,
        address: std.Io.net.IpAddress,
        base: u8,
        payloads: *[total_per_producer][1]u8,

        fn run(self: @This()) void {
            for (0..total_per_producer) |i| {
                self.payloads[i][0] = self.base;
                while (!self.queue.enqueue(.{ .to = self.address, .bytes = &self.payloads[i] })) {
                    std.atomic.spinLoopHint();
                }
            }
        }
    };

    // Storage must outlive the producer threads.
    var first_payloads: [total_per_producer][1]u8 = undefined;
    var second_payloads: [total_per_producer][1]u8 = undefined;

    var first = try std.Thread.spawn(.{}, Producer.run, .{Producer{ .queue = &queue, .address = address, .base = 1, .payloads = &first_payloads }});
    var second = try std.Thread.spawn(.{}, Producer.run, .{Producer{ .queue = &queue, .address = address, .base = 2, .payloads = &second_payloads }});

    var seen_first: usize = 0;
    var seen_second: usize = 0;
    var last_first: u8 = 0;
    var last_second: u8 = 0;
    while (seen_first + seen_second < 2 * total_per_producer) {
        if (queue.dequeue()) |datagram| {
            const value = datagram.bytes[0];
            if (value == 1) {
                try std.testing.expect(seen_first == 0 or last_first == 1);
                last_first = 1;
                seen_first += 1;
            } else {
                try std.testing.expect(seen_second == 0 or last_second == 2);
                last_second = 2;
                seen_second += 1;
            }
        } else {
            std.Thread.yield() catch {};
        }
    }

    first.join();
    second.join();
    try std.testing.expectEqual(total_per_producer, seen_first);
    try std.testing.expectEqual(total_per_producer, seen_second);
}
