const std = @import("std");
const Packets = @import("../Packets.zig").Packets;
const BinaryStream = @import("BinaryStream").BinaryStream;

// An MTU-sized datagram cannot reference more sequences than this.
pub const MAX_SEQUENCES_PER_ACK = 4096;

/// Borrowed view into the caller's scratch buffer; nothing to free.
pub const AckView = struct {
    sequences: []u32,
};

pub const Ack = struct {
    sequences: []u32,
    allocator: std.mem.Allocator,

    pub fn init(sequences: []const u32, allocator: std.mem.Allocator) !Ack {
        const seq = try allocator.alloc(u32, sequences.len);
        @memcpy(seq, sequences);
        return Ack{
            .sequences = seq,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Ack) void {
        self.allocator.free(self.sequences);
    }

    pub fn deserialize(data: []const u8, allocator: std.mem.Allocator) !Ack {
        var stream = BinaryStream.init(allocator, data, 0);
        defer stream.deinit();

        _ = try stream.readUint8(); // packet ID, plain UInt8
        const record_count = try stream.readUint16(.Big);

        var sequences = std.ArrayList(u32).initBuffer(&[_]u32{});
        defer {
            sequences.clearAndFree(allocator);
            sequences.deinit(allocator);
        }

        var index: usize = 0;
        while (index < record_count) : (index += 1) {
            const single = try stream.readBool();
            if (single) {
                if (sequences.items.len >= MAX_SEQUENCES_PER_ACK) return error.TooManySequences;
                const value = try stream.readUint24(.Little);
                try sequences.append(allocator, value);
            } else {
                const start = try stream.readUint24(.Little);
                const end = try stream.readUint24(.Little);
                if (end < start) return error.InvalidRange;
                if (end - start + 1 > MAX_SEQUENCES_PER_ACK) return error.RangeTooLarge;
                if (sequences.items.len + (end - start + 1) > MAX_SEQUENCES_PER_ACK) return error.TooManySequences;
                var seq_index = start;
                while (seq_index <= end) : (seq_index += 1) {
                    try sequences.append(allocator, seq_index);
                }
            }
        }

        return Ack.init(sequences.items, allocator);
    }

    /// Zero-alloc variant: `scratch.len` caps the number of sequences.
    pub fn deserializeView(data: []const u8, scratch: []u32) !AckView {
        var stream = BinaryStream{
            .payload = @constCast(data),
            .written = data.len,
            .offset = 0,
            .allocator = undefined,
            .owns_buffer = false,
        };

        _ = try stream.readUint8();
        const record_count = try stream.readUint16(.Big);

        var len: usize = 0;
        var index: usize = 0;
        while (index < record_count) : (index += 1) {
            const single = try stream.readBool();
            if (single) {
                if (len >= scratch.len or len >= MAX_SEQUENCES_PER_ACK) return error.TooManySequences;
                scratch[len] = try stream.readUint24(.Little);
                len += 1;
            } else {
                const start = try stream.readUint24(.Little);
                const end = try stream.readUint24(.Little);
                if (end < start) return error.InvalidRange;
                if (end - start + 1 > MAX_SEQUENCES_PER_ACK) return error.RangeTooLarge;
                if (len + (end - start + 1) > scratch.len or len + (end - start + 1) > MAX_SEQUENCES_PER_ACK) return error.TooManySequences;
                var seq_index = start;
                while (seq_index <= end) : (seq_index += 1) {
                    scratch[len] = seq_index;
                    len += 1;
                }
            }
        }

        return .{ .sequences = scratch[0..len] };
    }

    /// Zero-alloc; `sequences` must be sorted ascending.
    pub fn serializeInto(sequences: []const u32, packet_id: u8, out: []u8) ![]const u8 {
        var s = BinaryStream{
            .payload = out,
            .written = 0,
            .offset = 0,
            .allocator = undefined,
            .owns_buffer = false,
        };

        try s.writeUint8(packet_id);

        if (sequences.len == 0) {
            try s.writeUint16(0, .Big);
            return s.getBuffer();
        }

        // Count runs first so the record count can be written up front.
        var records: u16 = 0;
        var idx: usize = 0;
        while (idx < sequences.len) {
            records += 1;
            var run_end = idx;
            while (run_end + 1 < sequences.len and sequences[run_end + 1] == sequences[run_end] + 1) : (run_end += 1) {}
            idx = run_end + 1;
        }

        try s.writeUint16(records, .Big);

        idx = 0;
        while (idx < sequences.len) {
            var run_end = idx;
            while (run_end + 1 < sequences.len and sequences[run_end + 1] == sequences[run_end] + 1) : (run_end += 1) {}
            const start_value = sequences[idx];
            const end_value = sequences[run_end];
            if (start_value > 0xFFFFFF or end_value > 0xFFFFFF) return error.SequenceOutOfRange;
            if (start_value == end_value) {
                try s.writeUint8(1);
                try s.writeUint24(@truncate(start_value), .Little);
            } else {
                try s.writeUint8(0);
                try s.writeUint24(@truncate(start_value), .Little);
                try s.writeUint24(@truncate(end_value), .Little);
            }
            idx = run_end + 1;
        }

        return s.getBuffer();
    }

    pub fn serialize(self: *const Ack, allocator: std.mem.Allocator) ![]const u8 {
        // serializeInto requires ascending order.
        const sorted = try allocator.dupe(u32, self.sequences);
        defer allocator.free(sorted);
        std.mem.sort(u32, sorted, {}, comptime std.sort.asc(u32));

        const buffer = try allocator.alloc(u8, 4 + sorted.len * 7);
        defer allocator.free(buffer);
        return allocator.dupe(u8, try serializeInto(sorted, Packets.Ack, buffer));
    }
};

test "Ack" {
    const allocator = std.heap.page_allocator;
    const test_sequences = [_]u32{ 1, 2, 3, 5, 6, 10 };

    var ack = try Ack.init(&test_sequences, allocator);
    defer ack.deinit();

    const serialized = try ack.serialize(allocator);
    defer allocator.free(serialized);

    var deserialized = try Ack.deserialize(serialized, allocator);
    defer deserialized.deinit();

    try std.testing.expectEqual(ack.sequences.len, deserialized.sequences.len);
    for (ack.sequences, deserialized.sequences) |original, deserialized_seq| {
        try std.testing.expectEqual(original, deserialized_seq);
    }
}

test "Ack serializeInto round-trips ranges without allocating" {
    var buffer: [256]u8 = undefined;
    const sequences = [_]u32{ 1, 2, 3, 5, 6, 10 };
    const serialized = try Ack.serializeInto(&sequences, Packets.Ack, &buffer);

    const allocator = std.testing.allocator;
    var deserialized = try Ack.deserialize(serialized, allocator);
    defer deserialized.deinit();

    try std.testing.expectEqualSlices(u32, &sequences, deserialized.sequences);
}

test "Ack deserialize rejects oversized ranges" {
    const allocator = std.testing.allocator;
    const malicious = [_]u8{ Packets.Ack, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF };
    try std.testing.expectError(error.RangeTooLarge, Ack.deserialize(&malicious, allocator));
}

test "Ack deserializeView borrows the scratch and matches deserialize" {
    const allocator = std.testing.allocator;
    const sequences = [_]u32{ 1, 2, 3, 5, 6, 10 };
    var buffer: [256]u8 = undefined;
    const serialized = try Ack.serializeInto(&sequences, Packets.Ack, &buffer);

    var scratch: [16]u32 = undefined;
    const view = try Ack.deserializeView(serialized, &scratch);
    try std.testing.expectEqualSlices(u32, &sequences, view.sequences);

    var owned = try Ack.deserialize(serialized, allocator);
    defer owned.deinit();
    try std.testing.expectEqualSlices(u32, owned.sequences, view.sequences);
}

test "Ack deserializeView rejects lists that do not fit the scratch" {
    var buffer: [256]u8 = undefined;
    const sequences = [_]u32{ 1, 2, 3, 4, 5, 6 };
    const serialized = try Ack.serializeInto(&sequences, Packets.Nack, &buffer);

    var scratch: [4]u32 = undefined;
    try std.testing.expectError(error.TooManySequences, Ack.deserializeView(serialized, &scratch));
}
