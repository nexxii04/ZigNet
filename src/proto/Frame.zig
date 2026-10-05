const std = @import("std");
pub const BinaryStream = @import("BinaryStream").BinaryStream;

pub const Reliability = enum(u3) { Unreliable, UnreliableSequenced, Reliable, ReliableOrdered, ReliableSequenced, UnreliableWithAckReceipt, ReliableWithAckReceipt, ReliableOrderedWithAckReceipt };
const Flags = enum(u8) { Split = 0x10, Valid = 0x80, Ack = 0x40, Nack = 0x20 };

/// Reference-counted payload shared by several frames. The creator holds the
/// initial reference; the last `release` frees the bytes and the wrapper.
pub const SharedPayload = struct {
    bytes: []u8,
    refs: std.atomic.Value(u32),
    allocator: std.mem.Allocator,

    pub fn create(allocator: std.mem.Allocator, bytes: []u8) !*SharedPayload {
        const self = try allocator.create(SharedPayload);
        self.* = .{ .bytes = bytes, .refs = .init(1), .allocator = allocator };
        return self;
    }

    pub fn retain(self: *SharedPayload) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *SharedPayload) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            const allocator = self.allocator;
            allocator.free(self.bytes);
            allocator.destroy(self);
        }
    }
};

pub const Frame = struct {
    reliable_frame_index: ?u32,
    sequence_frame_index: ?u32,
    ordered_frame_index: ?u32,
    order_channel: ?u8,
    reliability: Reliability,
    payload: []const u8,
    split_frame_index: ?u32,
    split_id: ?u16,
    split_size: ?u32,
    allocator: ?std.mem.Allocator,
    /// If set, `deinit` releases this reference instead of freeing `payload`.
    shared: ?*SharedPayload = null,
    /// If set, the payload is these packets framed at serialization time
    /// (`[254][0xFF]` + varint-prefixed). Slices must outlive serialization.
    packets: ?[]const []const u8 = null,

    pub fn init(reliable_frame_index: ?u32, sequence_frame_index: ?u32, ordered_frame_index: ?u32, order_channel: ?u8, reliability: Reliability, payload: []const u8, split_frame_index: ?u32, split_id: ?u16, split_size: ?u32, allocator: ?std.mem.Allocator) Frame {
        return .{
            .reliable_frame_index = reliable_frame_index,
            .sequence_frame_index = sequence_frame_index,
            .ordered_frame_index = ordered_frame_index,
            .order_channel = order_channel,
            .reliability = reliability,
            .payload = payload,
            .split_frame_index = split_frame_index,
            .split_id = split_id,
            .split_size = split_size,
            .allocator = allocator,
        };
    }

    /// Payload is `packets` framed at send time, with no intermediate buffer.
    pub fn initPacketBatch(packets: []const []const u8, reliability: Reliability, order_channel: ?u8, allocator: ?std.mem.Allocator) Frame {
        var frame = Frame.init(null, null, null, order_channel, reliability, &.{}, null, null, null, allocator);
        frame.packets = packets;
        return frame;
    }

    /// Safe to call twice.
    pub fn deinit(self: *Frame) void {
        if (self.shared) |shared| {
            shared.release();
            self.shared = null;
            self.payload = &.{};
            self.allocator = null;
            return;
        }
        if (self.packets != null) {
            // Borrowed: nothing to free.
            self.packets = null;
            self.allocator = null;
            return;
        }
        if (self.allocator) |alloc| {
            if (self.payload.len > 0) {
                alloc.free(self.payload);
            }
            self.payload = &.{};
            self.allocator = null;
        }
    }

    pub fn read(stream: *BinaryStream) !Frame {
        const flags = try stream.readUint8();
        const reliability: Reliability = @as(Reliability, @enumFromInt((flags & 224) >> 5));
        const length = try stream.readUint16(.Big);
        // widen: length + 7 overflows u16
        const payload_length = (@as(u32, length) + 7) / 8;
        const split = (flags & @intFromEnum(Flags.Split)) != 0;

        if (payload_length + stream.offset > stream.written) {
            return error.FrameLengthExceedsStream;
        }

        var reliable_frame_index: ?u32 = null;
        var sequence_frame_index: ?u32 = null;
        var ordered_frame_index: ?u32 = null;
        var order_channel: ?u8 = null;
        var split_frame_index: ?u32 = null;
        var split_id: ?u16 = null;
        var split_size: ?u32 = null;

        switch (reliability) {
            .Reliable, .ReliableOrdered, .ReliableSequenced, .ReliableWithAckReceipt, .ReliableOrderedWithAckReceipt => {
                reliable_frame_index = try stream.readUint24(.Little);
            },
            else => {},
        }

        switch (reliability) {
            .UnreliableSequenced, .ReliableSequenced => {
                sequence_frame_index = try stream.readUint24(.Little);
            },
            else => {},
        }

        switch (reliability) {
            .ReliableOrdered, .ReliableOrderedWithAckReceipt => {
                ordered_frame_index = try stream.readUint24(.Little);
                order_channel = try stream.readUint8();
            },
            else => {},
        }

        if (split) {
            split_size = try stream.readUint32(.Big);
            split_id = try stream.readUint16(.Big);
            split_frame_index = try stream.readUint32(.Big);
        }

        const payload = stream.read(payload_length);

        // Payload borrows from stream - no copy, no allocator needed
        return Frame.init(reliable_frame_index, sequence_frame_index, ordered_frame_index, order_channel, reliability, payload, split_frame_index, split_id, split_size, null);
    }

    pub fn framedPayloadLength(self: *const Frame) usize {
        if (self.packets) |packets| {
            var total: usize = 2; // [254][0xFF] header
            for (packets) |packet| total += varintSize(packet.len) + packet.len;
            return total;
        }
        return self.payload.len;
    }

    pub fn write(self: *const Frame, stream: *BinaryStream) !void {
        const flags: u8 = ((@as(u8, @intFromEnum(self.reliability)) << 5) & 0xe0) |
            if (self.isSplit()) @intFromEnum(Flags.Split) else 0;
        try stream.writeUint8(flags);
        const length_in_bits = @as(u16, @intCast(self.framedPayloadLength())) * 8;
        try stream.writeUint16(length_in_bits, .Big);

        if (self.isReliable()) {
            try stream.writeUint24(@as(u24, @truncate(self.reliable_frame_index.?)), .Little);
        }
        if (self.isSequenced()) {
            try stream.writeUint24(@as(u24, @truncate(self.sequence_frame_index.?)), .Little);
        }
        if (self.isOrdered()) {
            try stream.writeUint24(@as(u24, @truncate(self.ordered_frame_index.?)), .Little);
            try stream.writeUint8(self.order_channel.?);
        }
        if (self.isSplit()) {
            try stream.writeUint32(self.split_size.?, .Big);
            try stream.writeUint16(self.split_id.?, .Big);
            try stream.writeUint32(self.split_frame_index.?, .Big);
        }
        if (self.packets) |packets| {
            try stream.writeUint8(254);
            try stream.writeUint8(0xFF);
            for (packets) |packet| {
                try stream.writeVarInt(@intCast(packet.len));
                try stream.write(packet);
            }
            return;
        }
        try stream.write(self.payload);
    }

    pub fn isSplit(self: *const Frame) bool {
        return self.split_size != null and self.split_size.? > 0;
    }

    pub fn isReliable(self: *const Frame) bool {
        return switch (self.reliability) {
            .Reliable, .ReliableOrdered, .ReliableSequenced, .ReliableWithAckReceipt, .ReliableOrderedWithAckReceipt => true,
            else => false,
        };
    }

    pub fn isSequenced(self: *const Frame) bool {
        return switch (self.reliability) {
            .ReliableSequenced, .UnreliableSequenced => true,
            else => false,
        };
    }

    pub fn isOrdered(self: *const Frame) bool {
        return switch (self.reliability) {
            .UnreliableSequenced, .ReliableOrdered, .ReliableSequenced, .ReliableOrderedWithAckReceipt => true,
            else => false,
        };
    }

    pub fn isOrderExclusive(self: *const Frame) bool {
        return switch (self.reliability) {
            .ReliableOrdered, .ReliableOrderedWithAckReceipt => true,
            else => false,
        };
    }

    pub fn getByteLength(self: *const Frame) usize {
        return 3 +
            self.framedPayloadLength() +
            (if (self.isReliable()) @as(usize, 3) else 0) +
            (if (self.isSequenced()) @as(usize, 3) else 0) +
            (if (self.isOrdered()) @as(usize, 4) else 0) +
            (if (self.isSplit()) @as(usize, 10) else 0);
    }
};

test "Frame rejects lengths beyond the stream instead of panicking" {
    const allocator = std.testing.allocator;
    const malformed = [_]u8{ 0x84, 0xFF, 0xFF, 0x00, 0x01 };
    var stream = BinaryStream.init(allocator, &malformed, null);
    defer stream.deinit();

    try std.testing.expectError(error.FrameLengthExceedsStream, Frame.read(&stream));
}

test "Frame deinit is idempotent" {
    const allocator = std.testing.allocator;
    const payload = try allocator.dupe(u8, "owned payload");
    var frame = Frame.init(0, null, null, 0, .Reliable, payload, null, null, null, allocator);
    frame.deinit();
    frame.deinit();
    try std.testing.expectEqual(@as(usize, 0), frame.payload.len);
}

fn varintSize(value: usize) usize {
    if (value < 0x80) return 1;
    if (value < 0x4000) return 2;
    if (value < 0x200000) return 3;
    if (value < 0x10000000) return 4;
    return 5;
}

test "a packet batch frame serializes the unframed compression framing inline" {
    const allocator = std.testing.allocator;
    const packets = [_][]const u8{ "hello", "", &[_]u8{0xAB} ** 200 };

    var frame = Frame.initPacketBatch(&packets, .ReliableOrdered, 0, null);
    frame.reliable_frame_index = 7;
    frame.ordered_frame_index = 3;

    var expected_payload: std.ArrayList(u8) = .empty;
    defer expected_payload.deinit(allocator);
    try expected_payload.append(allocator, 254);
    try expected_payload.append(allocator, 0xFF);
    for (packets) |packet| {
        if (packet.len < 0x80) {
            try expected_payload.append(allocator, @intCast(packet.len));
        } else {
            try expected_payload.append(allocator, @intCast((packet.len & 0x7F) | 0x80));
            try expected_payload.append(allocator, @intCast(packet.len >> 7));
        }
        try expected_payload.appendSlice(allocator, packet);
    }

    try std.testing.expectEqual(expected_payload.items.len, frame.framedPayloadLength());

    var buffer: [1024]u8 = undefined;
    var stream = BinaryStream{
        .payload = &buffer,
        .written = 0,
        .offset = 0,
        .allocator = undefined,
        .owns_buffer = false,
    };
    try frame.write(&stream);

    var reader = BinaryStream.init(allocator, stream.getBuffer(), null);
    const decoded = try Frame.read(&reader);
    try std.testing.expectEqual(Reliability.ReliableOrdered, decoded.reliability);
    try std.testing.expectEqual(@as(?u32, 7), decoded.reliable_frame_index);
    try std.testing.expectEqual(@as(?u32, 3), decoded.ordered_frame_index);
    try std.testing.expectEqualSlices(u8, expected_payload.items, decoded.payload);

    // deinit of a borrowed batch releases nothing and is idempotent.
    frame.deinit();
    frame.deinit();
}

test "a shared payload outlives the frames that reference it" {
    const allocator = std.testing.allocator;
    const bytes = try allocator.dupe(u8, "shared across frames");
    const shared = try SharedPayload.create(allocator, bytes);

    var first = Frame.init(1, null, null, null, .Reliable, shared.bytes[0..6], null, null, null, null);
    first.shared = shared;
    shared.retain();
    var second = Frame.init(2, null, null, null, .Reliable, shared.bytes[6..], null, null, null, null);
    second.shared = shared;
    shared.retain();

    // Release the creator's reference: the two frames keep it alive.
    shared.release();
    first.deinit();
    try std.testing.expectEqualSlices(u8, " across frames", second.payload);
    second.deinit();
}
