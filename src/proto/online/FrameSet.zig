const BinaryStream = @import("BinaryStream").BinaryStream;
const Packets = @import("../Packets.zig").Packets;
const Frame = @import("../Frame.zig").Frame;
const std = @import("std");

pub const FrameSet = struct {
    stream: BinaryStream,
    sequence_number: u24,
    frames: []const Frame,
    owns_frames: bool,

    pub fn init(sequence_number: u24, frames: []const Frame, allocator: std.mem.Allocator) FrameSet {
        return .{
            .stream = BinaryStream.init(allocator, null, null),
            .sequence_number = sequence_number,
            .frames = frames,
            .owns_frames = false,
        };
    }

    pub fn serialize(self: *FrameSet) ![]const u8 {
        try self.stream.writeUint8(Packets.FrameSet);
        try self.stream.writeUint24(self.sequence_number, .Little);

        for (self.frames) |frame| {
            try frame.write(&self.stream);
        }

        return self.stream.getBuffer();
    }

    /// Writes into `out` (zero allocs); returns a slice of it.
    pub fn serializeInto(sequence_number: u24, frames: []const Frame, out: []u8) ![]const u8 {
        var s = BinaryStream{
            .payload = out,
            .written = 0,
            .offset = 0,
            .allocator = undefined,
            .owns_buffer = false,
        };

        try s.writeUint8(Packets.FrameSet);
        try s.writeUint24(sequence_number, .Little);
        for (frames) |frame| {
            try frame.write(&s);
        }
        return s.getBuffer();
    }

    /// Zero-alloc: frames go into `frames_buf` and payloads borrow `buffer`.
    /// Returns `error.TooManyFrames` if they don't fit.
    pub fn deserializeInto(buffer: []const u8, frames_buf: []Frame) !FrameSet {
        var stream = BinaryStream{
            .payload = @constCast(buffer),
            .written = buffer.len,
            .offset = 0,
            .allocator = undefined,
            .owns_buffer = false,
        };

        _ = try stream.readUint8(); // packet type
        const sequence_number = try stream.readUint24(.Little);

        var count: usize = 0;
        const end_position = stream.written;
        while (stream.offset < end_position) {
            if (count >= frames_buf.len) return error.TooManyFrames;
            frames_buf[count] = try Frame.read(&stream);
            count += 1;
        }

        return FrameSet{
            .stream = stream,
            .sequence_number = sequence_number,
            .frames = frames_buf[0..count],
            .owns_frames = false,
        };
    }

    pub fn deserialize(buffer: []const u8, allocator: std.mem.Allocator) !FrameSet {
        var stream = BinaryStream.init(allocator, buffer, null);
        errdefer stream.deinit();

        _ = try stream.readUint8(); // Skip packet type
        const sequence_number = try stream.readUint24(.Little);

        var frames = std.ArrayList(Frame).initBuffer(&[_]Frame{});
        errdefer frames.deinit(allocator);

        const end_position = stream.written;
        while (stream.offset < end_position) {
            const frame = try Frame.read(&stream);
            try frames.append(allocator, frame);
        }

        return FrameSet{
            .stream = stream,
            .sequence_number = sequence_number,
            .frames = try frames.toOwnedSlice(allocator),
            .owns_frames = true,
        };
    }

    pub fn deinit(self: *FrameSet, allocator: std.mem.Allocator) void {
        if (self.owns_frames) {
            allocator.free(self.frames);
        }
        self.stream.deinit();
    }
};

test "FrameSet" {
    const allocator = std.heap.page_allocator;

    // Create test payload
    const test_payload = try allocator.dupe(u8, "Hello, World!");
    defer allocator.free(test_payload);

    // Create a simple reliable frame
    const frame = Frame.init(1, // reliable_frame_index
        null, // sequence_frame_index
        null, // ordered_frame_index
        null, // order_channel
        .Reliable, // reliability
        test_payload, null, // split_frame_index
        null, // split_id
        null, // split_size
        allocator);

    const frames = [_]Frame{frame};
    var frameset = FrameSet.init(42, &frames, allocator);

    const serialized = try frameset.serialize();

    // deserialized payloads borrow from frameset.stream: it must outlive them
    var deserialized = try FrameSet.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(@as(u24, 42), deserialized.sequence_number);
    try std.testing.expectEqual(frames.len, deserialized.frames.len);
    try std.testing.expectEqual(frames[0].reliability, deserialized.frames[0].reliability);
    try std.testing.expectEqual(frames[0].reliable_frame_index, deserialized.frames[0].reliable_frame_index);
    try std.testing.expectEqualSlices(u8, frames[0].payload, deserialized.frames[0].payload);

    frameset.deinit(allocator);
}

test "FrameSet deserializeInto borrows frames and input without allocating" {
    const allocator = std.testing.allocator;

    const first_payload = "first";
    const second_payload = "second payload";
    const frames = [_]Frame{
        Frame.init(1, null, null, null, .Reliable, first_payload, null, null, null, null),
        Frame.init(2, null, null, null, .Reliable, second_payload, null, null, null, null),
    };

    var buffer: [256]u8 = undefined;
    const serialized = try FrameSet.serializeInto(77, &frames, &buffer);

    var frames_scratch: [8]Frame = undefined;
    var deserialized = try FrameSet.deserializeInto(serialized, &frames_scratch);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(@as(u24, 77), deserialized.sequence_number);
    try std.testing.expectEqual(@as(usize, 2), deserialized.frames.len);
    try std.testing.expectEqualSlices(u8, first_payload, deserialized.frames[0].payload);
    try std.testing.expectEqualSlices(u8, second_payload, deserialized.frames[1].payload);
}

test "FrameSet deserializeInto rejects framesets bigger than the scratch" {
    const frames = [_]Frame{
        Frame.init(1, null, null, null, .Reliable, "a", null, null, null, null),
        Frame.init(2, null, null, null, .Reliable, "b", null, null, null, null),
    };

    var buffer: [256]u8 = undefined;
    const serialized = try FrameSet.serializeInto(1, &frames, &buffer);

    var frames_scratch: [1]Frame = undefined;
    try std.testing.expectError(error.TooManyFrames, FrameSet.deserializeInto(serialized, &frames_scratch));
}

test "FrameSet serializeInto writes into the caller buffer" {
    const allocator = std.testing.allocator;

    const test_payload = try allocator.dupe(u8, "Hello, World!");
    defer allocator.free(test_payload);

    const frame = Frame.init(7, null, null, null, .Reliable, test_payload, null, null, null, null);
    const frames = [_]Frame{frame};

    var buffer: [256]u8 = undefined;
    const serialized = try FrameSet.serializeInto(42, &frames, &buffer);

    var deserialized = try FrameSet.deserialize(serialized, allocator);
    defer deserialized.deinit(allocator);

    try std.testing.expectEqual(@as(u24, 42), deserialized.sequence_number);
    try std.testing.expectEqual(@as(usize, 1), deserialized.frames.len);
    try std.testing.expectEqualSlices(u8, test_payload, deserialized.frames[0].payload);
}
