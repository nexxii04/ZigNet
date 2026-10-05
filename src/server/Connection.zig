const std = @import("std");
const Timestamp = std.Io.Timestamp;

const Logger = @import("../misc/Logger.zig").Logger;
const Proto = @import("../proto/root.zig");
const Frame = Proto.Frame;
const Reliability = Proto.Reliability;
const ServerModule = @import("./Server.zig");
const Server = ServerModule.Server;
const SharedPayload = Proto.SharedPayload;
const OutputSlab = @import("./OutputSlab.zig").OutputSlab;

/// Local helper mirroring the game framing's unsigned LEB128 sizes.
fn varintSize(value: usize) usize {
    if (value < 0x80) return 1;
    if (value < 0x4000) return 2;
    if (value < 0x200000) return 3;
    if (value < 0x10000000) return 4;
    return 5;
}

fn writeVarInt(buffer: []u8, value: usize) usize {
    var val = value;
    var pos: usize = 0;
    while (val >= 0x80) {
        buffer[pos] = @intCast((val & 0x7F) | 0x80);
        val >>= 7;
        pos += 1;
    }
    buffer[pos] = @intCast(val & 0x7F);
    return pos + 1;
}

const MAX_CHANNELS = 32;
const MAX_ORDERING_QUEUE_SIZE = 64;
const MAX_PENDING_GAME_BYTES = 1024 * 1024;
const MAX_SPLIT_SIZE: u32 = 1024;
const MAX_FRAGMENT_SETS = 256;
const FRAGMENT_TIMEOUT_NS: i64 = 10 * std.time.ns_per_s;
const MAX_LOST_GAP: u32 = 4096;
const MAX_PENDING_SEQUENCES = 8192;
const RECEIVE_WINDOW_SIZE = 8192;
const SEQUENCE_HALF_RANGE: u24 = 1 << 23;

fn sequenceAhead(sequence: u24, previous: u24) bool {
    const distance = sequence -% previous;
    return distance != 0 and distance < SEQUENCE_HALF_RANGE;
}

const ReceiveWindow = struct {
    newest: ?u24 = null,
    seen: std.StaticBitSet(RECEIVE_WINDOW_SIZE) = .initEmpty(),

    fn record(self: *ReceiveWindow, sequence: u24) bool {
        if (self.newest) |previous| {
            if (sequenceAhead(sequence, previous)) {
                const distance = sequence -% previous;
                if (distance >= RECEIVE_WINDOW_SIZE) {
                    self.seen = .initEmpty();
                } else {
                    var step: u24 = 1;
                    while (step <= distance) : (step += 1) {
                        self.seen.unset((previous +% step) % RECEIVE_WINDOW_SIZE);
                    }
                }
                self.newest = sequence;
            } else if (previous -% sequence >= RECEIVE_WINDOW_SIZE) {
                return false;
            }
        } else {
            self.newest = sequence;
        }
        const slot = sequence % RECEIVE_WINDOW_SIZE;
        if (self.seen.isSet(slot)) return false;
        self.seen.set(slot);
        return true;
    }
};
const RETRANSMIT_TIMEOUT_NS: i64 = 200 * std.time.ns_per_ms;
const MAX_RETRANSMITS: u8 = 10;
const MAX_RETRANSMITS_PER_TICK: usize = 32;
// Thread-local scratch for the socket thread; oversized framesets fall back to the heap.
const FRAMESET_SCRATCH_FRAMES: usize = 512;
const ACK_SCRATCH_SEQUENCES: usize = Proto.MAX_SEQUENCES_PER_ACK;
threadlocal var frameset_scratch: [FRAMESET_SCRATCH_FRAMES]Frame = undefined;
threadlocal var ack_scratch: [ACK_SCRATCH_SEQUENCES]u32 = undefined;
// 3 + 384*4 = 1539: worst-case ACK datagram; a bigger batch would fail to
// serialize every tick and never ack.
const MAX_ACK_BATCH: usize = 384;
const MAX_FRAMES_PER_TICK: usize = 512;
const MAX_SEND_NS: i64 = 5 * std.time.ns_per_ms;
const DATAGRAM_SCRATCH_SIZE = 1600;

comptime {
    std.debug.assert((1 << 24) % RECEIVE_WINDOW_SIZE == 0);
    std.debug.assert(RECEIVE_WINDOW_SIZE < SEQUENCE_HALF_RANGE);
    std.debug.assert(3 + MAX_ACK_BATCH * 4 <= DATAGRAM_SCRATCH_SIZE);
    std.debug.assert(DATAGRAM_SCRATCH_SIZE >= ServerModule.MAX_MTU_SIZE);
}

const PERFORM_TIME_CHECKS = false;
const DEBUG = false;

// Game packet callback for Connection (packet ID 254)
pub const GamePacketCallback = *const fn (connection: *Connection, payload: []const u8, context: ?*anyopaque) void;

pub const BackupEntry = struct {
    bytes: []const u8,
    sent_ns: i64,
    retries: u8,
    slot: ?u32 = null,
};

const ChannelQueue = std.AutoHashMap(u32, Frame);
const FragmentSet = std.AutoHashMap(u16, Frame);

fn initMapCapacity(comptime K: type, comptime V: type, allocator: std.mem.Allocator, capacity: u32) std.AutoHashMap(K, V) {
    var map = std.AutoHashMap(K, V).init(allocator);
    map.ensureTotalCapacity(capacity) catch {}; // best effort: grows on demand
    return map;
}

/// Moves up to `out.len` keys out of a pending-sequence set (caller holds the
/// shard lock). One batch is serialized per tick and the batch cap fits the
/// datagram scratch at comptime, so removing here cannot lose a sequence.
fn collectSequences(set: *std.AutoHashMap(u24, void), out: []u32) usize {
    var len: usize = 0;
    var iter = set.keyIterator();
    while (iter.next()) |key| {
        if (len == out.len) break;
        out[len] = key.*;
        len += 1;
    }
    for (out[0..len]) |sequence| _ = set.remove(@truncate(sequence));
    return len;
}

pub const Connection = struct {
    const Self = @This();
    server: *Server,
    address: std.Io.net.IpAddress,
    key: i64,
    mtu_size: u16,
    guid: i64,
    connected: std.atomic.Value(bool),
    active: std.atomic.Value(bool),
    comm_data: CommData,
    last_receive_ns: std.atomic.Value(u64),
    created_at: Timestamp,
    game_packet_callback: ?GamePacketCallback = null,
    game_packet_context: ?*anyopaque = null,
    tick_counter: u64 = 0,
    last_ping_time: std.Io.Timestamp = .zero,
    ping_interval: std.Io.Duration = .fromMilliseconds(5000),
    send_mutex: std.Io.Mutex = .init,
    pending_connect_event: bool = false,
    pending_game_packets: std.ArrayList([]u8) = .empty,
    pending_game_bytes: usize = 0,
    pending_movement: ?[]u8 = null,

    pub fn init(server: *Server, address: std.Io.net.IpAddress, mtu_size: u16, guid: i64) Self {
        return Self{
            .server = server,
            .address = address,
            .key = Server.addressToKey(address),
            .mtu_size = mtu_size,
            .guid = guid,
            .connected = std.atomic.Value(bool).init(false),
            .active = std.atomic.Value(bool).init(true),
            .comm_data = .{
                .received_sequences = initMapCapacity(u24, void, server.options.allocator, 16),
                .lost_sequences = initMapCapacity(u24, void, server.options.allocator, 16),
                .input_order_index = [_]u32{0} ** MAX_CHANNELS,
                .input_highest_sequence_index = [_]u32{0} ** MAX_CHANNELS,
                .input_ordering_channels = [_]?ChannelQueue{null} ** MAX_CHANNELS,
                .output_reliable_index = 0,
                .output_sequence = 0,
                .output_frame_queue = std.ArrayList(Frame).initBuffer(&[_]Frame{}),
                .output_backup = initMapCapacity(u24, BackupEntry, server.options.allocator, 64),
                .output_order_index = [_]u32{0} ** MAX_CHANNELS,
                .output_sequence_index = [_]u32{0} ** MAX_CHANNELS,
                .output_split_index = 0,
                .fragments_queue = initMapCapacity(u16, FragmentSet, server.options.allocator, 8),
                .fragments_activity = initMapCapacity(u16, Timestamp, server.options.allocator, 8),
            },
            .last_receive_ns = std.atomic.Value(u64).init(@intCast(Timestamp.now(server.io, .awake).nanoseconds)),
            .created_at = Timestamp.now(server.io, .awake),
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.pending_game_packets.items) |bytes| self.server.options.allocator.free(bytes);
        self.pending_game_packets.deinit(self.server.options.allocator);
        if (self.pending_movement) |pending| {
            self.server.options.allocator.free(pending);
            self.pending_movement = null;
        }
        self.comm_data.deinit(self.server.options.allocator, &self.server.output_slab);
    }

    pub fn handlePacket(self: *Self, payload: []const u8) !void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;
        if (payload.len == 0) return;
        const ID = payload[0];

        const allocator = self.server.options.allocator;

        switch (ID) {
            Proto.Packets.ConnectionRequest => {
                var request = try Proto.ConnectionRequest.deserialize(payload);
                defer request.deinit();

                const empty_address = Proto.Address.init(4, "0.0.0.0", 0);
                var accepted = Proto.ConnectionRequestAccepted.init(
                    empty_address,
                    0,
                    empty_address,
                    request.timestamp,
                    Timestamp.now(self.server.io, .real).toMilliseconds(),
                );

                defer accepted.deinit(allocator);

                var accepted_buf: [Proto.ConnectionRequestAccepted.MAX_SERIALIZED_SIZE]u8 = undefined;
                const serialized = try accepted.serializeInto(&accepted_buf);
                const frame = try self.frameIn(serialized);

                self.sendFrame(frame, .Immediate);
            },
            Proto.Packets.NewIncomingConnection => {
                self.connected.store(true, .release);
                const elapsed = self.created_at.untilNow(self.server.io, .awake);

                if (DEBUG)
                    Logger.DEBUG("Connection established in {d}ms", .{elapsed.toMilliseconds()});

                // fired by Server after it releases connections_mutex
                self.pending_connect_event = true;
            },
            Proto.Packets.DisconnectNotification => {
                self.connected.store(false, .release);
                self.deactivate();
            },
            254 => {
                if (self.pending_connect_event) {
                    if (self.pending_game_packets.items.len >= MAX_ORDERING_QUEUE_SIZE or
                        payload.len > MAX_PENDING_GAME_BYTES - self.pending_game_bytes) return error.PendingGameQueueFull;

                    const copy = try allocator.dupe(u8, payload);
                    errdefer allocator.free(copy);

                    try self.pending_game_packets.append(allocator, copy);
                    self.pending_game_bytes += copy.len;
                    return;
                }

                // Game packet - trigger connection game packet callback
                if (self.game_packet_callback) |callback| {
                    callback(self, payload, self.game_packet_context);
                }
            },
            Proto.Packets.ConnectedPing => {
                var ping = Proto.ConnectedPing.deserialize(payload) catch |err| {
                    Logger.ERROR("Failed to deserialize ConnectedPing: {any}", .{err});
                    return;
                };

                defer ping.deinit();

                const current_time_ms = Timestamp.now(self.server.io, .real).toMilliseconds();
                var pong = Proto.ConnectedPong.init(ping.timestamp, current_time_ms);
                defer pong.deinit();

                var pong_buf: [Proto.ConnectedPong.MAX_SERIALIZED_SIZE]u8 = undefined;
                const serialized = pong.serializeInto(&pong_buf) catch |err| {
                    Logger.ERROR("Failed to serialize ConnectedPong: {any}", .{err});
                    return;
                };

                const frame = try self.frameIn(serialized);
                self.sendFrame(frame, .Immediate);
            },
            Proto.Packets.ConnectedPong => {
                var pong = Proto.ConnectedPong.deserialize(payload) catch |err| {
                    Logger.ERROR("Failed to deserialize ConnectedPong: {any}", .{err});
                    return;
                };

                defer pong.deinit();

                const current_time_ms = Timestamp.now(self.server.io, .real).toMilliseconds();
                const rtt = current_time_ms - pong.timestamp; // Round trip time

                if (DEBUG)
                    Logger.DEBUG("Received ConnectedPong - RTT: {d}ms", .{rtt});
            },
            else => {
                Logger.WARN("Unhandeled Packet {d}", .{ID});
            },
        }
        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handlePacket took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn tick(self: *Connection) void {
        if (!self.isActive()) return;

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;
        const now = Timestamp.now(self.server.io, .awake);
        const last_receive = Timestamp.fromNanoseconds(@intCast(self.last_receive_ns.load(.acquire)));
        const elapsed = last_receive.untilNow(self.server.io, .awake);

        if (elapsed.toMilliseconds() > 15000) {
            Logger.WARN("Connection {any} has not received any packets in 15000ms", .{self.address});
            self.deactivate();
            return;
        }

        // Fragment state is guarded by the shard lock, which the socket handler also holds.
        {
            const token = self.server.registry.lock(self.server.io, self.key);
            defer self.server.registry.unlock(self.server.io, token);
            self.purgeStaleFragments(now);
        }
        self.flushPendingMovement();

        self.send_mutex.lock(self.server.io) catch |err| {
            Logger.WARN("mutex lock failed: {}", .{err});
            return;
        };

        if (self.queuedFrameCount() > 0) {
            self.sendQueueLocked(MAX_FRAMES_PER_TICK, MAX_SEND_NS);
        }

        self.retransmitTimedOut(now);

        self.send_mutex.unlock(self.server.io);

        // Collected under the shard lock, serialized outside it. MAX_ACK_BATCH fits
        // DATAGRAM_SCRATCH_SIZE at comptime, so serialization cannot fail.
        var ack_storage: [MAX_ACK_BATCH]u32 = undefined;
        var ack_len: usize = 0;
        var nack_storage: [MAX_ACK_BATCH]u32 = undefined;
        var nack_len: usize = 0;
        {
            const token = self.server.registry.lock(self.server.io, self.key);
            defer self.server.registry.unlock(self.server.io, token);
            ack_len = collectSequences(&self.comm_data.received_sequences, &ack_storage);
            nack_len = collectSequences(&self.comm_data.lost_sequences, &nack_storage);
        }
        if (ack_len > 0) {
            const batch = ack_storage[0..ack_len];
            std.mem.sort(u32, batch, {}, comptime std.sort.asc(u32));
            var ack_buf: [DATAGRAM_SCRATCH_SIZE]u8 = undefined;
            const serialized = Proto.Ack.serializeInto(batch, Proto.Packets.Ack, &ack_buf) catch |err| {
                Logger.ERROR("Failed to serialize ack: {any}", .{err});
                return;
            };
            self.sendTransient(serialized);
        }
        if (nack_len > 0) {
            const batch = nack_storage[0..nack_len];
            std.mem.sort(u32, batch, {}, comptime std.sort.asc(u32));
            var nack_buf: [DATAGRAM_SCRATCH_SIZE]u8 = undefined;
            const serialized = Proto.Ack.serializeInto(batch, Proto.Packets.Nack, &nack_buf) catch |err| {
                Logger.ERROR("Failed to serialize nack: {any}", .{err});
                return;
            };
            self.sendTransient(serialized);
        }

        if (self.isConnected()) {
            const since_last_ping = self.last_ping_time.durationTo(now);

            if (since_last_ping.nanoseconds >= self.ping_interval.nanoseconds) {
                self.sendPing();
                self.last_ping_time = now;
            }
        }

        self.tick_counter += 1;

        if (start_time) |start| {
            const tick_elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: tick took {d} ms", .{tick_elapsed.toMilliseconds()});
        }
    }

    pub fn handleAck(self: *Self, payload: []const u8) !void {
        if (!self.isActive()) return;

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        const ack = try Proto.Ack.deserializeView(payload, &ack_scratch);

        // output_backup belongs to send_mutex
        self.send_mutex.lock(self.server.io) catch |err| {
            Logger.WARN("mutex lock failed: {}", .{err});
            return;
        };
        defer self.send_mutex.unlock(self.server.io);

        for (ack.sequences) |seq| {
            const key: u24 = @truncate(seq);
            if (self.comm_data.output_backup.fetchRemove(key)) |entry| self.releaseBackup(entry.value);
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handleAck took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn handleNack(self: *Self, payload: []const u8) !void {
        if (!self.isActive()) return;

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        const nack = try Proto.Ack.deserializeView(payload, &ack_scratch);

        self.send_mutex.lock(self.server.io) catch |err| {
            Logger.WARN("mutex lock failed: {}", .{err});
            return;
        };
        defer self.send_mutex.unlock(self.server.io);

        const now = Timestamp.now(self.server.io, .awake);
        for (nack.sequences) |seq| {
            const key: u24 = @truncate(seq);
            if (self.comm_data.output_backup.getPtr(key)) |entry| {
                self.sendPrepared(entry.bytes, entry.slot);
                entry.sent_ns = @intCast(now.nanoseconds);
                entry.retries += 1;
            }
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handleNack took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn onFrameSet(self: *Self, buffer: []const u8) !void {
        if (!self.isActive()) return;

        self.last_receive_ns.store(@intCast(Timestamp.now(self.server.io, .awake).nanoseconds), .release);
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        // Frames use the thread-local scratch; oversized framesets fall back to the heap.
        var frameSet = Proto.FrameSet.deserializeInto(buffer, &frameset_scratch) catch |err| switch (err) {
            error.TooManyFrames => try Proto.FrameSet.deserialize(buffer, self.server.options.allocator),
            else => return err,
        };
        defer frameSet.deinit(self.server.options.allocator);

        const sequence = frameSet.sequence_number;
        const previous = self.comm_data.datagram_history.newest;
        const advances = previous == null or sequenceAhead(sequence, previous.?);
        const distance: u24 = if (previous) |last| sequence -% last else sequence +% 1;
        const gap: u32 = if (distance > 0) distance - 1 else 0;

        if (advances and gap > 0 and gap <= MAX_LOST_GAP) {
            const capacity = @min(gap, MAX_PENDING_SEQUENCES - self.comm_data.lost_sequences.count());
            try self.comm_data.lost_sequences.ensureUnusedCapacity(@intCast(capacity));
        }

        if (self.comm_data.received_sequences.count() >= MAX_PENDING_SEQUENCES and
            !self.comm_data.received_sequences.contains(sequence)) return error.PendingAckQueueFull;
        try self.comm_data.received_sequences.put(sequence, {});
        _ = self.comm_data.lost_sequences.remove(sequence);

        if (!self.comm_data.datagram_history.record(sequence)) return;

        if (advances) {
            // Expire NACKs as their sequences leave the bounded receive window.
            // Iterate the evicted slots rather than scanning the whole map.
            if (previous) |last| {
                if (distance >= RECEIVE_WINDOW_SIZE) {
                    self.comm_data.lost_sequences.clearRetainingCapacity();
                } else {
                    var step: u24 = 1;
                    while (step <= distance) : (step += 1) {
                        _ = self.comm_data.lost_sequences.remove(last +% step -% RECEIVE_WINDOW_SIZE);
                    }
                }
            }
            if (gap > 0 and gap <= MAX_LOST_GAP) {
                var missing: u24 = if (previous) |last| last +% 1 else 0;
                var i: u32 = 0;
                while (i < gap) : (i += 1) {
                    if (self.comm_data.lost_sequences.count() >= MAX_PENDING_SEQUENCES) break;
                    self.comm_data.lost_sequences.putAssumeCapacity(missing, {});
                    missing +%= 1;
                }
            }
            self.comm_data.last_input_sequence = @intCast(sequence);
        }
        for (frameSet.frames) |frame| {
            try self.handleFrame(frame);
        }

        if (start_time) |s_time| {
            const elapsed = s_time.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: onFrameSet took {d} ms", .{elapsed.toMicroseconds()});
        }
    }

    pub fn handleFrame(self: *Connection, frame: Frame) !void {
        if (!self.isActive()) return;

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        if (frame.payload.len == 0) {
            Logger.WARN("Frame has empty payload - skipping in handleFrame", .{});
            return;
        }

        if (frame.isReliable()) {
            const index = frame.reliable_frame_index orelse return error.MissingReliableIndex;
            if (index > std.math.maxInt(u24)) return error.InvalidReliableIndex;
            if (!self.comm_data.reliable_history.record(@intCast(index))) return;
        }

        if (frame.isSplit()) {
            try self.handleSplitFrame(frame);
        } else if (frame.isSequenced()) {
            self.handleSequencedFrame(frame);
        } else if (frame.isOrdered()) {
            self.handleOrderedFrame(frame);
        } else {
            self.handlePacket(frame.payload) catch {
                Logger.ERROR("Failed to handle packet", .{});
                return;
            };
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handleFrame took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn handleOrderedFrame(self: *Connection, frame: Frame) void {
        if (!self.isActive()) return;

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        const channel = frame.order_channel orelse {
            Logger.ERROR("Ordered frame missing order_channel", .{});
            return;
        };

        if (channel >= MAX_CHANNELS) {
            Logger.WARN("Ordered frame with invalid channel {d} dropped", .{channel});
            return;
        }

        const frame_index = frame.ordered_frame_index orelse {
            Logger.ERROR("Ordered frame missing ordered_frame_index", .{});
            return;
        };

        if (frame_index > std.math.maxInt(u24)) return;
        const expected: u24 = @truncate(self.comm_data.input_order_index[channel]);
        const order: u24 = @intCast(frame_index);
        if (order == expected) {
            self.comm_data.input_highest_sequence_index[channel] = 0;
            self.comm_data.input_order_index[channel] = order +% 1;

            self.handlePacket(frame.payload) catch {
                Logger.ERROR("Failed to handle packet", .{});
                return;
            };

            var index = self.comm_data.input_order_index[channel];
            if (self.orderingChannel(channel)) |queue| {
                while (queue.contains(index)) {
                    var iframe = queue.get(index).?;
                    _ = queue.remove(index);
                    self.handlePacket(iframe.payload) catch |err| {
                        Logger.ERROR("Failed to handle ordered queued packet: {any}", .{err});
                        iframe.deinit();
                        return;
                    };
                    iframe.deinit();
                    index = @as(u24, @truncate(index)) +% 1;
                }
                self.comm_data.input_order_index[channel] = index;
            }
        } else if (sequenceAhead(order, expected)) {
            if (self.orderingChannel(channel)) |queue| {
                if (queue.contains(frame_index)) return;
                if (queue.count() >= MAX_ORDERING_QUEUE_SIZE) {
                    Logger.WARN("Ordering queue full on channel {d}, dropping frame", .{channel});
                    return;
                }
                const allocator = self.server.options.allocator;
                const payload_copy = allocator.dupe(u8, frame.payload) catch {
                    Logger.ERROR("Failed to dupe payload for ordering queue", .{});
                    return;
                };

                var frame_copy = frame;
                frame_copy.payload = payload_copy;
                frame_copy.allocator = allocator;

                queue.put(frame_index, frame_copy) catch |err| {
                    Logger.ERROR("Failed to put frame in ordering queue: {any}", .{err});
                    allocator.free(payload_copy);
                    return;
                };
            }
        }
        // Stale order indexes have already been delivered: never replay them.

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handleOrderedFrame took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn handleSequencedFrame(self: *Self, frame: Frame) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        const channel = frame.order_channel orelse 0;
        if (channel >= MAX_CHANNELS) {
            Logger.WARN("Sequenced frame with invalid channel {d} dropped", .{channel});
            return;
        }

        const frame_index = frame.sequence_frame_index orelse {
            Logger.ERROR("Sequenced frame missing sequence_frame_index", .{});
            return;
        };

        const order_index = frame.ordered_frame_index orelse {
            Logger.ERROR("Sequenced frame missing ordered_frame_index", .{});
            return;
        };

        const current_highest = self.comm_data.input_highest_sequence_index[channel];
        if (frame_index >= current_highest and order_index >= self.comm_data.input_order_index[channel]) {
            self.comm_data.input_highest_sequence_index[channel] = frame_index + 1;
            self.handlePacket(frame.payload) catch |err| {
                Logger.ERROR("Failed to handle packet: {any}", .{err});
                return;
            };
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: handleSequencedFrame took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn handleSplitFrame(self: *Self, frame: Frame) !void {
        const split_id = frame.split_id orelse {
            Logger.ERROR("Split frame missing split_id", .{});
            return;
        };

        const split_index = frame.split_frame_index orelse {
            Logger.ERROR("Split frame missing split_frame_index", .{});
            return;
        };

        const split_size = frame.split_size orelse {
            Logger.ERROR("Split frame missing split_size", .{});
            return;
        };

        if (split_size == 0 or split_size > MAX_SPLIT_SIZE) {
            Logger.WARN("Split frame with invalid split_size {d} dropped", .{split_size});
            return;
        }
        if (split_index >= split_size) {
            Logger.WARN("Split frame with invalid split_index {d} dropped", .{split_index});
            return;
        }

        const allocator = self.server.options.allocator;
        const index_u16: u16 = @intCast(split_index);

        if (self.comm_data.fragments_queue.getPtr(split_id)) |fragment| {
            // Duplicate fragment, ignore
            if (fragment.contains(index_u16)) {
                return;
            }

            const payload_copy = allocator.dupe(u8, frame.payload) catch {
                Logger.ERROR("Failed to duplicate frame payload", .{});
                return;
            };

            var frame_copy = Frame.init(
                frame.reliable_frame_index,
                frame.sequence_frame_index,
                frame.ordered_frame_index,
                frame.order_channel,
                frame.reliability,
                payload_copy,
                frame.split_frame_index,
                frame.split_id,
                frame.split_size,
                allocator,
            );

            fragment.put(index_u16, frame_copy) catch {
                Logger.ERROR("Failed to put frame in fragment queue", .{});
                frame_copy.deinit();
                return;
            };
            self.comm_data.fragments_activity.put(split_id, Timestamp.now(self.server.io, .awake)) catch {};

            if (fragment.count() == split_size) {
                var total_length: usize = 0;
                var complete = true;
                var index: u16 = 0;
                while (index < split_size) : (index += 1) {
                    const sframe = fragment.get(index) orelse {
                        complete = false;
                        break;
                    };
                    total_length += sframe.payload.len;
                }

                if (!complete) {
                    Logger.WARN("Fragment set {d} incomplete despite count match", .{split_id});
                    return;
                }

                const reconstructed = allocator.alloc(u8, total_length) catch {
                    Logger.ERROR("Failed to allocate reconstructed payload", .{});
                    return;
                };

                var offset: usize = 0;
                index = 0;
                while (index < split_size) : (index += 1) {
                    const sframe = fragment.get(index).?;
                    @memcpy(reconstructed[offset .. offset + sframe.payload.len], sframe.payload);
                    offset += sframe.payload.len;
                }

                var nframe = Frame.init(
                    frame.reliable_frame_index,
                    frame.sequence_frame_index,
                    frame.ordered_frame_index,
                    frame.order_channel,
                    frame.reliability,
                    reconstructed,
                    null, // split_frame_index - not split anymore
                    null, // split_id - not split anymore
                    null, // split_size - not split anymore
                    allocator,
                );

                // fragments are consumed; nframe owns its payload now
                self.removeFragmentSet(split_id);

                if (nframe.isSequenced()) {
                    self.handleSequencedFrame(nframe);
                } else if (nframe.isOrdered()) {
                    self.handleOrderedFrame(nframe);
                } else {
                    self.handlePacket(nframe.payload) catch {
                        Logger.ERROR("Failed to handle reconstructed packet", .{});
                    };
                }

                nframe.deinit();
            }
        } else {
            if (self.comm_data.fragments_queue.count() >= MAX_FRAGMENT_SETS) {
                Logger.WARN("Too many incomplete fragment sets, dropping split_id {d}", .{split_id});
                return;
            }

            var new_fragment = FragmentSet.init(allocator);
            errdefer new_fragment.deinit();

            const payload_copy = allocator.dupe(u8, frame.payload) catch {
                Logger.ERROR("Failed to duplicate frame payload", .{});
                return;
            };
            var frame_copy = Frame.init(
                frame.reliable_frame_index,
                frame.sequence_frame_index,
                frame.ordered_frame_index,
                frame.order_channel,
                frame.reliability,
                payload_copy,
                frame.split_frame_index,
                frame.split_id,
                frame.split_size,
                allocator,
            );

            new_fragment.put(index_u16, frame_copy) catch {
                Logger.ERROR("Failed to create new fragment queue", .{});
                frame_copy.deinit();
                return;
            };
            self.comm_data.fragments_queue.put(split_id, new_fragment) catch {
                Logger.ERROR("Failed to add fragment to queue", .{});
                frame_copy.deinit();
                new_fragment.deinit();
                return;
            };
            self.comm_data.fragments_activity.put(split_id, Timestamp.now(self.server.io, .awake)) catch {};
        }
    }

    fn removeFragmentSet(self: *Self, split_id: u16) void {
        if (self.comm_data.fragments_queue.fetchRemove(split_id)) |entry| {
            var fragment = entry.value;
            var iter = fragment.iterator();
            while (iter.next()) |frag_entry| {
                frag_entry.value_ptr.deinit();
            }
            fragment.deinit();
        }
        _ = self.comm_data.fragments_activity.remove(split_id);
    }

    fn purgeStaleFragments(self: *Self, now: Timestamp) void {
        var stale: [64]u16 = undefined;
        var stale_count: usize = 0;

        var iter = self.comm_data.fragments_activity.iterator();
        while (iter.next()) |entry| {
            const age_ns: i64 = @intCast(now.nanoseconds - entry.value_ptr.nanoseconds);
            if (age_ns > FRAGMENT_TIMEOUT_NS and stale_count < stale.len) {
                stale[stale_count] = entry.key_ptr.*;
                stale_count += 1;
            }
        }

        for (stale[0..stale_count]) |id| {
            Logger.WARN("Fragment set {d} timed out incomplete, dropping", .{id});
            self.removeFragmentSet(id);
        }
    }

    fn orderingChannel(self: *Self, channel: usize) ?*ChannelQueue {
        const slot = &self.comm_data.input_ordering_channels[channel];
        if (slot.*) |*existing| {
            return existing;
        }
        slot.* = ChannelQueue.init(self.server.options.allocator);
        return &(slot.*.?);
    }

    pub fn frameIn(self: *Connection, msg: []const u8) !Frame {
        const allocator = self.server.options.allocator;
        const payload_copy = try allocator.dupe(u8, msg);
        return Frame.init(null, null, null, 0, Reliability.ReliableOrdered, payload_copy, null, null, null, allocator);
    }

    pub fn sendReliableMessage(self: *Connection, msg: []const u8, priority: Priority) void {
        if (!self.isActive()) return;

        var frame = self.frameIn(msg) catch |err| {
            Logger.ERROR("Failed to allocate reliable message: {any}", .{err});
            return;
        };
        frame.reliability = Reliability.ReliableOrdered;

        self.sendFrame(frame, priority);
    }

    /// Takes ownership of `msg`; freed once the frame is serialized or dropped.
    pub fn sendReliableMessageOwned(self: *Connection, msg: []const u8, priority: Priority) void {
        if (!self.server.options.output_arena) {
            self.sendReliableMessage(msg, priority);
            self.server.options.allocator.free(msg);
            return;
        }
        if (!self.isActive()) {
            self.server.options.allocator.free(msg);
            return;
        }

        var frame = Frame.init(null, null, null, 0, Reliability.ReliableOrdered, msg, null, null, null, self.server.options.allocator);
        frame.reliability = Reliability.ReliableOrdered;
        self.sendFrame(frame, priority);
    }

    /// Retains `shared` until the frame is retired; the caller keeps its own reference.
    pub fn sendReliableMessageShared(self: *Connection, shared: *SharedPayload, priority: Priority) void {
        if (!self.server.options.output_arena) {
            self.sendReliableMessage(shared.bytes, priority);
            return;
        }
        if (!self.isActive()) return;

        shared.retain();
        var frame = Frame.init(null, null, null, 0, Reliability.ReliableOrdered, shared.bytes, null, null, null, null);
        frame.reliability = Reliability.ReliableOrdered;
        frame.shared = shared;
        self.sendFrame(frame, priority);
    }

    /// Writes the batch straight into an output slab slot. `packets` is only
    /// read during this call.
    pub fn sendPacketBatch(self: *Connection, packets: []const []const u8, priority: Priority) void {
        if (!self.isActive()) return;
        if (!self.server.options.output_arena) {
            self.sendBatchCopied(packets, priority);
            return;
        }

        var frame = Frame.initPacketBatch(packets, Reliability.ReliableOrdered, 0, null);
        if (!self.sendBorrowedFrame(&frame)) {
            // Batch too large for a slot, or pool exhausted.
            self.sendBatchCopied(packets, priority);
        }
    }

    fn sendBatchCopied(self: *Connection, packets: []const []const u8, priority: Priority) void {
        const allocator = self.server.options.allocator;
        var framed_size: usize = 2; // [254][0xFF] header
        for (packets) |packet| framed_size += varintSize(packet.len) + packet.len;

        const buffer = allocator.alloc(u8, framed_size) catch return;
        buffer[0] = 254;
        buffer[1] = 0xFF;
        var pos: usize = 2;
        for (packets) |packet| {
            pos += writeVarInt(buffer[pos..], packet.len);
            @memcpy(buffer[pos..][0..packet.len], packet);
            pos += packet.len;
        }

        var frame = Frame.init(null, null, null, 0, Reliability.ReliableOrdered, buffer, null, null, null, allocator);
        frame.reliability = Reliability.ReliableOrdered;
        self.sendFrame(frame, priority);
    }

    pub fn sendMovementReliableMessage(self: *Connection, msg: []const u8) void {
        if (!self.isActive()) return;
        const allocator = self.server.options.allocator;
        const copy = allocator.dupe(u8, msg) catch {
            self.comm_data.movement_dropped += 1;
            return;
        };
        self.send_mutex.lock(self.server.io) catch {
            allocator.free(copy);
            self.comm_data.movement_dropped += 1;
            return;
        };
        if (self.pending_movement) |previous| {
            allocator.free(previous);
            self.comm_data.movement_coalesced += 1;
        }
        self.pending_movement = copy;
        self.send_mutex.unlock(self.server.io);
    }

    fn flushPendingMovement(self: *Connection) void {
        self.send_mutex.lock(self.server.io) catch return;
        const pending = self.pending_movement orelse {
            self.send_mutex.unlock(self.server.io);
            return;
        };
        self.pending_movement = null;
        self.send_mutex.unlock(self.server.io);

        const frame = Frame.init(null, null, null, 0, Reliability.ReliableOrdered, pending, null, null, null, self.server.options.allocator);
        self.sendFrame(frame, .Normal);
    }

    pub fn sendFrame(self: *Connection, frame: Frame, priority: Priority) void {
        if (!self.isActive()) {
            var f = frame;
            f.deinit();
            return;
        }

        self.send_mutex.lock(self.server.io) catch |err| {
            Logger.WARN("mutex lock failed: {}", .{err});
            var f = frame;
            f.deinit();
            return;
        };

        defer self.send_mutex.unlock(self.server.io);

        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        const channel = frame.order_channel orelse 0;
        if (channel >= MAX_CHANNELS) {
            Logger.WARN("sendFrame with invalid channel {d} dropped", .{channel});
            var f = frame;
            f.deinit();
            return;
        }

        var mutable_frame = frame;

        if (mutable_frame.isSequenced()) {
            mutable_frame.ordered_frame_index = self.comm_data.output_order_index[channel];
            mutable_frame.sequence_frame_index = self.comm_data.output_sequence_index[channel];

            self.comm_data.output_sequence_index[channel] += 1;
        } else if (mutable_frame.isOrdered()) {
            mutable_frame.ordered_frame_index = self.comm_data.output_order_index[channel];

            self.comm_data.output_order_index[channel] += 1;
            self.comm_data.output_sequence_index[channel] = 0;
        }

        const payload_size = mutable_frame.payload.len;
        const max_size = self.mtu_size - 36;

        if (payload_size <= max_size) {
            if (mutable_frame.isReliable()) {
                mutable_frame.reliable_frame_index = self.comm_data.output_reliable_index;
                self.comm_data.output_reliable_index += 1;
            }
            self.queueFrameLocked(mutable_frame, priority);
        } else {
            const split_size = (payload_size + max_size - 1) / max_size;
            self.handleLargePayload(&mutable_frame, max_size, split_size, priority);
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: sendFrame took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    const FramesetBackup = struct {
        bytes: []const u8,
        slot: ?u32 = null,
    };

    /// Slab slot if available, heap copy otherwise. Null means nothing was sent.
    /// Caller holds send_mutex.
    fn buildFramesetBackup(self: *Connection, sequence: u24, frames: []const Frame) ?FramesetBackup {
        const allocator = self.server.options.allocator;
        if (self.server.options.output_arena) {
            if (self.server.output_slab.claim()) |slot| {
                const bytes = Proto.FrameSet.serializeInto(sequence, frames, self.server.output_slab.slotBytes(slot)) catch |err| {
                    Logger.ERROR("Failed to serialize frameset: {any}", .{err});
                    self.server.output_slab.release(slot);
                    return null;
                };
                return .{ .bytes = bytes, .slot = slot };
            }
        }

        var scratch: [DATAGRAM_SCRATCH_SIZE]u8 = undefined;
        const serialized = Proto.FrameSet.serializeInto(sequence, frames, &scratch) catch |err| {
            Logger.ERROR("Failed to serialize frameset: {any}", .{err});
            return null;
        };
        const backup = allocator.dupe(u8, serialized) catch |err| {
            Logger.ERROR("Backup alloc failed: {any}", .{err});
            return null;
        };
        return .{ .bytes = backup };
    }

    fn releaseBackup(self: *Connection, entry: BackupEntry) void {
        if (entry.slot) |slot| {
            self.server.output_slab.release(slot);
            return;
        }
        if (entry.bytes.len > 0) {
            self.server.options.allocator.free(@constCast(entry.bytes));
        }
    }

    /// Sends a borrowed frame immediately, bypassing the queue. Returns false
    /// (without consuming ordering indices) if it doesn't fit a slot.
    fn sendBorrowedFrame(self: *Connection, frame: *Frame) bool {
        if (!self.isActive()) return true;

        self.send_mutex.lock(self.server.io) catch {
            Logger.WARN("mutex lock failed on borrowed send", .{});
            return false;
        };
        defer self.send_mutex.unlock(self.server.io);

        const max_frameset_size = @min(self.mtu_size - 28, DATAGRAM_SCRATCH_SIZE);
        if (4 + frame.getByteLength() > max_frameset_size) return false;

        const channel: usize = 0;
        frame.order_channel = 0;
        frame.ordered_frame_index = self.comm_data.output_order_index[channel];
        frame.reliable_frame_index = self.comm_data.output_reliable_index;

        const slot = self.server.output_slab.claim() orelse return false;
        const sequence: u24 = @truncate(self.comm_data.output_sequence);
        const frames = [_]Frame{frame.*};
        const serialized = Proto.FrameSet.serializeInto(sequence, &frames, self.server.output_slab.slotBytes(slot)) catch |err| {
            Logger.ERROR("Failed to serialize packet batch: {any}", .{err});
            self.server.output_slab.release(slot);
            return false;
        };

        self.comm_data.output_order_index[channel] += 1;
        self.comm_data.output_sequence_index[channel] = 0;
        self.comm_data.output_reliable_index += 1;
        self.comm_data.output_sequence += 1;

        const now = Timestamp.now(self.server.io, .awake);
        var backed_up = true;
        if (self.comm_data.output_backup.fetchRemove(sequence)) |old| self.releaseBackup(old.value);
        self.comm_data.output_backup.put(sequence, .{
            .bytes = serialized,
            .sent_ns = @intCast(now.nanoseconds),
            .retries = 0,
            .slot = slot,
        }) catch |err| {
            Logger.WARN("Backup store failed, sending without reliability: {any}", .{err});
            backed_up = false;
        };

        self.sendPrepared(serialized, slot);
        self.comm_data.output_frames_sent += 1;
        if (!backed_up) self.releaseBackup(.{ .bytes = serialized, .slot = slot, .sent_ns = 0, .retries = 0 });
        return true;
    }

    pub fn handleLargePayload(
        self: *Connection,
        frame: *Frame,
        max_size: usize,
        split_size: usize,
        priority: Priority,
    ) void {
        const allocator = self.server.options.allocator;
        const split_id = self.comm_data.output_split_index;

        self.comm_data.output_split_index = (self.comm_data.output_split_index +% 1);

        // Store original payload reference before we start fragmenting
        const original_payload = frame.payload;

        // Fragments are slices of the original buffer, each holding one reference;
        // the last fragment retired frees it. The legacy path duplicates per fragment.
        if (self.server.options.output_arena) {
            const wrapper = SharedPayload.create(allocator, @constCast(original_payload)) catch {
                allocator.free(original_payload);
                frame.payload = &.{};
                frame.allocator = null;
                return;
            };
            // Drops the frame's original reference once every fragment holds its own.
            defer wrapper.release();

            var index: usize = 0;
            while (index < original_payload.len) {
                const end_index = @min(index + max_size, original_payload.len);
                wrapper.retain();
                var new_frame = Frame.init(frame.reliable_frame_index, frame.sequence_frame_index, frame.ordered_frame_index, frame.order_channel, frame.reliability, original_payload[index..end_index], @as(u32, @intCast(index / max_size)), // split_frame_index
                    split_id, // split_id
                    @as(u32, @intCast(split_size)), // split_size
                    null);
                new_frame.shared = wrapper;

                if (new_frame.isReliable()) {
                    new_frame.reliable_frame_index = self.comm_data.output_reliable_index;
                    self.comm_data.output_reliable_index += 1;
                }

                self.queueFrameLocked(new_frame, priority);
                index += max_size;
            }
            return;
        }

        // Legacy path: one duplicate per fragment; the original goes away.
        defer {
            allocator.free(original_payload);
            frame.payload = &.{};
            frame.allocator = null;
        }

        var index: usize = 0;
        while (index < original_payload.len) {
            const end_index = @min(index + max_size, original_payload.len);
            const fragment_payload = original_payload[index..end_index];

            const payload_copy = allocator.dupe(u8, fragment_payload) catch {
                Logger.ERROR("Failed to duplicate fragment payload", .{});
                return;
            };

            var new_frame = Frame.init(frame.reliable_frame_index, frame.sequence_frame_index, frame.ordered_frame_index, frame.order_channel, frame.reliability, payload_copy, @as(u32, @intCast(index / max_size)), // split_frame_index
                split_id, // split_id
                @as(u32, @intCast(split_size)), // split_size
                allocator);

            if (new_frame.isReliable()) {
                new_frame.reliable_frame_index = self.comm_data.output_reliable_index;
                self.comm_data.output_reliable_index += 1;
            }

            self.queueFrameLocked(new_frame, priority);
            index += max_size;
        }
    }

    // caller holds send_mutex
    fn queueFrameLocked(self: *Connection, frame: Frame, priority: Priority) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;

        // Don't queue frames if connection is not active - prevents leaks during shutdown
        if (!self.isActive()) {
            var f = frame;
            f.deinit();
            return;
        }

        self.comm_data.output_frame_queue.append(self.server.options.allocator, frame) catch {
            Logger.ERROR("Failed to queue frame", .{});
            var f = frame;
            f.deinit();
            return;
        };
        self.comm_data.output_frames_queued += 1;
        self.comm_data.output_queue_peak = @max(self.comm_data.output_queue_peak, self.queuedFrameCount());

        const should_send_immediately = priority == Priority.Immediate;
        if (should_send_immediately) {
            self.sendQueueLocked(self.queuedFrameCount(), 0);
        }

        if (start_time) |start| {
            const elapsed = start.untilNow(self.server.io, .awake);
            Logger.DEBUG("PERF: queueFrame took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    fn queuedFrameCount(self: *Connection) usize {
        return self.comm_data.output_frame_queue.items.len - self.comm_data.output_queue_head;
    }

    fn advanceQueueHead(self: *Connection, count: usize) void {
        const c = &self.comm_data;
        c.output_queue_head += count;

        // memmove only once the dead prefix is large (amortized O(1))
        if (c.output_queue_head == c.output_frame_queue.items.len) {
            c.output_frame_queue.clearRetainingCapacity();
            c.output_queue_head = 0;
        } else if (c.output_queue_head >= 64 and c.output_queue_head * 2 >= c.output_frame_queue.items.len) {
            c.output_frame_queue.replaceRange(self.server.options.allocator, 0, c.output_queue_head, &[_]Frame{}) catch {
                return;
            };
            c.output_queue_head = 0;
        }
    }

    // caller holds send_mutex
    fn sendQueueLocked(self: *Connection, amount: usize, budget_ns: i64) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.server.io, .awake) else null;
        const now = Timestamp.now(self.server.io, .awake);
        const budget_started = now;

        const max_frameset_size = self.mtu_size - 28; // Leave room for UDP/IP headers

        var processed: usize = 0;
        while (processed < amount) {
            if (budget_ns > 0 and processed > 0) {
                const elapsed_ns = budget_started.untilNow(self.server.io, .awake).nanoseconds;
                if (elapsed_ns >= budget_ns) break;
            }
            const available = self.queuedFrameCount();
            if (available == 0) break;

            const head = self.comm_data.output_queue_head;
            const candidate = @min(available, amount - processed);

            var fit: usize = 0;
            var current_size: usize = 4; // Frameset header size
            for (self.comm_data.output_frame_queue.items[head .. head + candidate]) |frame| {
                const frame_size = frame.getByteLength();
                if (current_size + frame_size > max_frameset_size and fit > 0) {
                    break;
                }
                current_size += frame_size;
                fit += 1;
            }
            if (fit == 0) fit = 1;

            const frames = self.comm_data.output_frame_queue.items[head .. head + fit];

            const sequence: u24 = @truncate(self.comm_data.output_sequence);
            self.comm_data.output_sequence += 1;

            const backup = self.buildFramesetBackup(sequence, frames) orelse {
                for (frames) |*frame| frame.deinit();
                self.advanceQueueHead(fit);
                processed += fit;
                continue;
            };

            // retire whatever previously occupied this sequence slot (u24 wrap)
            if (self.comm_data.output_backup.fetchRemove(sequence)) |old| self.releaseBackup(old.value);

            var backed_up = true;
            self.comm_data.output_backup.put(sequence, .{
                .bytes = backup.bytes,
                .sent_ns = @intCast(now.nanoseconds),
                .retries = 0,
                .slot = backup.slot,
            }) catch |err| {
                Logger.WARN("Backup store failed, sending without reliability: {any}", .{err});
                backed_up = false;
            };

            self.sendPrepared(backup.bytes, backup.slot);
            self.comm_data.output_frames_sent += fit;
            if (!backed_up) self.releaseBackup(.{ .bytes = backup.bytes, .slot = backup.slot, .sent_ns = 0, .retries = 0 });

            for (frames) |*frame| {
                frame.deinit();
            }
            self.advanceQueueHead(fit);
            processed += fit;
        }

        if (start_time) |start| {
            const end_time = Timestamp.now(self.server.io, .awake);
            const elapsed = start.durationTo(end_time);
            Logger.DEBUG("PERF: sendQueue took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    fn retransmitTimedOut(self: *Connection, now: Timestamp) void {
        var resent: usize = 0;
        var dropped_key: ?u24 = null;

        var iter = self.comm_data.output_backup.iterator();
        while (iter.next()) |entry| {
            if (resent >= MAX_RETRANSMITS_PER_TICK) break;

            const age_ns: i64 = @intCast(now.nanoseconds - entry.value_ptr.sent_ns);
            if (age_ns < RETRANSMIT_TIMEOUT_NS) continue;

            if (entry.value_ptr.retries >= MAX_RETRANSMITS) {
                Logger.WARN("Connection {any} unresponsive (sequence {d} unacked after {d} retries)", .{ self.address, entry.key_ptr.*, entry.value_ptr.retries });
                dropped_key = entry.key_ptr.*;
                self.deactivate();
                break;
            }

            self.sendPrepared(entry.value_ptr.bytes, entry.value_ptr.slot);
            entry.value_ptr.sent_ns = @intCast(now.nanoseconds);
            entry.value_ptr.retries += 1;
            resent += 1;
        }

        if (dropped_key) |key| {
            if (self.comm_data.output_backup.fetchRemove(key)) |entry| self.releaseBackup(entry.value);
        }
    }

    /// Queues a frameset already serialized in an output slab slot, which the
    /// queue retains while in flight. Sends directly if the sender thread is
    /// disabled or the ring is full.
    pub fn sendPrepared(self: *Connection, bytes: []const u8, slot: ?u32) void {
        self.server.submitDatagram(self.address, bytes, slot);
    }

    /// Copies `bytes` into the transient pool, since the caller's buffer is on the stack.
    pub fn sendTransient(self: *Connection, bytes: []const u8) void {
        self.server.submitTransient(self.address, bytes);
    }

    /// Called after onConnect has installed the handler, under the shard lock
    /// just like normal game delivery. Each copy is released exactly once.
    pub fn drainPendingGamePackets(self: *Self) void {
        defer {
            for (self.pending_game_packets.items) |bytes| self.server.options.allocator.free(bytes);
            self.pending_game_packets.clearRetainingCapacity();
            self.pending_game_bytes = 0;
        }
        for (self.pending_game_packets.items) |bytes| {
            if (!self.isActive()) break;
            if (self.game_packet_callback) |callback| callback(self, bytes, self.game_packet_context);
        }
    }

    pub fn takePendingConnect(self: *Self) bool {
        const was_pending = self.pending_connect_event;
        self.pending_connect_event = false;
        return was_pending;
    }

    /// Set game packet callback (for packet ID 254)
    pub fn setGamePacketCallback(self: *Connection, callback: ?GamePacketCallback, context: ?*anyopaque) void {
        self.game_packet_callback = callback;
        self.game_packet_context = context;
    }

    pub fn getAddress(self: *const Connection) std.Io.net.IpAddress {
        return self.address;
    }

    pub fn isConnected(self: *const Connection) bool {
        return self.connected.load(.acquire);
    }

    pub fn isActive(self: *const Connection) bool {
        return self.active.load(.acquire);
    }

    /// Callable from any thread; the shard owner retires the connection on its next pass.
    pub fn deactivate(self: *Connection) void {
        self.active.store(false, .release);
    }

    /// Send a ConnectedPing packet to the client
    pub fn sendPing(self: *Connection) void {
        const timestamp = Timestamp.now(self.server.io, .real).toMilliseconds();

        var ping = Proto.ConnectedPing.init(timestamp);
        defer ping.deinit();

        var ping_buf: [Proto.ConnectedPing.MAX_SERIALIZED_SIZE]u8 = undefined;
        const serialized = ping.serializeInto(&ping_buf) catch |err| {
            Logger.ERROR("Failed to serialize ConnectedPing: {any}", .{err});
            return;
        };

        const frame = self.frameIn(serialized) catch |err| {
            Logger.ERROR("Failed to allocate ping frame: {any}", .{err});
            return;
        };
        self.sendFrame(frame, .Normal);
    }
};

pub const CommData = struct {
    last_input_sequence: i32 = -1,
    datagram_history: ReceiveWindow = .{},
    reliable_history: ReceiveWindow = .{},
    received_sequences: std.AutoHashMap(u24, void),
    lost_sequences: std.AutoHashMap(u24, void),
    input_order_index: [MAX_CHANNELS]u32,
    input_highest_sequence_index: [MAX_CHANNELS]u32,
    input_ordering_channels: [MAX_CHANNELS]?ChannelQueue,

    output_reliable_index: u32,
    output_sequence: u32,
    output_frame_queue: std.ArrayList(Frame),
    output_queue_head: usize = 0,
    output_frames_queued: u64 = 0,
    output_frames_sent: u64 = 0,
    output_queue_peak: usize = 0,
    output_backup: std.AutoHashMap(u24, BackupEntry),
    output_order_index: [MAX_CHANNELS]u32,
    output_sequence_index: [MAX_CHANNELS]u32,
    output_split_index: u16,

    fragments_queue: std.AutoHashMap(u16, FragmentSet),
    fragments_activity: std.AutoHashMap(u16, Timestamp),
    movement_coalesced: u64 = 0,
    movement_dropped: u64 = 0,

    pub fn deinit(self: *CommData, allocator: std.mem.Allocator, slab: *OutputSlab) void {
        self.received_sequences.deinit();
        self.lost_sequences.deinit();

        // frames below the head were freed on send
        for (self.output_frame_queue.items[self.output_queue_head..]) |*frame| {
            frame.deinit();
        }
        self.output_frame_queue.deinit(allocator);

        for (&self.input_ordering_channels) |*maybe_queue| {
            if (maybe_queue.*) |*queue| {
                var inner_iterator = queue.iterator();
                while (inner_iterator.next()) |inner_entry| {
                    inner_entry.value_ptr.deinit();
                }
                queue.deinit();
            }
        }

        var backup_iter = self.output_backup.iterator();
        while (backup_iter.next()) |entry| {
            if (entry.value_ptr.slot) |slot| {
                slab.release(slot);
            } else if (entry.value_ptr.bytes.len > 0) {
                allocator.free(@constCast(entry.value_ptr.bytes));
            }
        }
        self.output_backup.deinit();

        var fragments_iter = self.fragments_queue.iterator();
        while (fragments_iter.next()) |outer_entry| {
            var inner_fragments_iter = outer_entry.value_ptr.iterator();
            while (inner_fragments_iter.next()) |inner_entry| {
                inner_entry.value_ptr.deinit();
            }
            outer_entry.value_ptr.deinit();
        }
        self.fragments_queue.deinit();
        self.fragments_activity.deinit();
    }
};

pub const Priority = enum(u8) {
    Immediate = 0,
    Normal = 1,
};
