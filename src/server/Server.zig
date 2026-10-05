const std = @import("std");
const Thread = std.Thread;
const Timestamp = std.Io.Timestamp;
const Duration = std.Io.Duration;
const builtin = @import("builtin");

const Logger = @import("../misc/Logger.zig").Logger;
const Proto = @import("../proto/root.zig");
const Packets = Proto.Packets;
const Socket = @import("../socket/socket.zig").Socket;
const Connection = @import("./Connection.zig").Connection;
const ConnectionRegistryModule = @import("./ConnectionRegistry.zig");
const ConnectionRegistry = ConnectionRegistryModule.ConnectionRegistry;
const OutputSlab = @import("./OutputSlab.zig").OutputSlab;
const OutboundQueueModule = @import("./OutboundQueue.zig");
const OutboundQueue = OutboundQueueModule.OutboundQueue;
const OutboundDatagram = OutboundQueueModule.Datagram;

const OUTPUT_SLOT_SIZE: usize = 1600;
const OUTPUT_SLOT_COUNT: u32 = 4096;
const OUTBOUND_QUEUE_SLOTS: usize = 8192;
const TRANSIENT_SLOT_COUNT: u32 = 4096;
const SENDER_MAX_BATCH: usize = 512;
const SENDER_IDLE_SLEEP_NS: u64 = 100_000;
pub const DEFAULT_SHARDS: u8 = 4;

const is_windows = builtin.os.tag == .windows;

const PERFORM_TIME_CHECKS = false;

pub const UDP_HEADER_SIZE = 28;
pub const MAX_MTU_SIZE = 1400;
pub const ConnectCallback = *const fn (connection: *Connection, context: ?*anyopaque) void;
pub const DisconnectCallback = *const fn (connection: *Connection, context: ?*anyopaque) void;
pub const TickCallback = *const fn (context: ?*anyopaque) void;

// Per-IP offline rate limit: caps floods, legit traffic never hits it.
const MAX_RATE_TRACKED = 256;
const RATE_CAPACITY_TOKENS: i32 = 150;
const RATE_TOKENS_PER_S: i64 = 100;

const RateEntry = struct {
    key: i64,
    tokens: i32,
    last_ns: i64,
};

pub const Server = struct {
    const Self = @This();
    io: std.Io,
    options: ServerOptions,
    socket: Socket,
    running: std.atomic.Value(bool) = .init(false),
    registry: ConnectionRegistry,
    shard_workers: []std.Thread = &.{},
    output_slab: OutputSlab,
    outbound: OutboundQueue,
    /// For datagrams not already in the output slab; the sender frees the slot.
    transient_slab: OutputSlab,
    sender_thread: ?std.Thread = null,
    tick_thread: ?std.Io.Future(void) = null,
    connect_callback: ?ConnectCallback,
    connect_context: ?*anyopaque,
    disconnect_callback: ?DisconnectCallback,
    disconnect_context: ?*anyopaque,
    tick_callback: ?TickCallback,
    tick_context: ?*anyopaque,
    last_connection_tick_ns: Duration = .zero,
    last_callback_tick_ns: Duration = .zero,
    last_total_tick_ns: Duration = .zero,
    retired_scratch: std.ArrayList(*Connection) = .empty,
    rate_entries: [MAX_RATE_TRACKED]RateEntry = undefined,
    rate_count: usize = 0,

    /// IPv4 packs ip and port into the lower 48 bits; IPv6 uses FNV-1a.
    pub inline fn addressToKey(address: std.Io.net.IpAddress) i64 {
        return switch (address) {
            .ip4 => |ip4| blk: {
                const ip: u32 = @bitCast(ip4.bytes);
                const port = ip4.port;
                break :blk @as(i64, ip) | (@as(i64, port) << 32);
            },
            .ip6 => |ip6| blk: {
                var hash: u64 = 0xcbf29ce484222325;
                for (ip6.bytes) |byte| {
                    hash ^= byte;
                    hash *%= 0x100000001b3;
                }
                hash ^= ip6.port;
                hash *%= 0x100000001b3;
                break :blk @bitCast(hash);
            },
        };
    }

    pub fn init(io: std.Io, options: ServerOptions) !Server {
        const slot_count = if (options.output_slab_slots == 0) OUTPUT_SLOT_COUNT else options.output_slab_slots;
        const transient_slots = if (options.transient_slab_slots == 0) TRANSIENT_SLOT_COUNT else options.transient_slab_slots;
        const queue_slots = if (options.outbound_queue_slots == 0) OUTBOUND_QUEUE_SLOTS else options.outbound_queue_slots;

        var output_slab = try OutputSlab.init(options.allocator, slot_count, OUTPUT_SLOT_SIZE);
        errdefer output_slab.deinit(options.allocator);
        var transient_slab = try OutputSlab.init(options.allocator, transient_slots, OUTPUT_SLOT_SIZE);
        errdefer transient_slab.deinit(options.allocator);
        var outbound = try OutboundQueue.init(options.allocator, queue_slots);
        errdefer outbound.deinit(options.allocator);

        var registry = try ConnectionRegistry.init(options.allocator, clampShardCount(options.shards));
        errdefer registry.deinit();

        var server = Server{
            .io = io,
            .options = options,
            .socket = try Socket.init(
                io,
                options.allocator,
                options.address,
                options.port,
            ),
            .registry = registry,
            .output_slab = output_slab,
            .outbound = outbound,
            .transient_slab = transient_slab,
            .connect_callback = options.connect_callback,
            .connect_context = options.connect_context,
            .disconnect_callback = options.disconnect_callback,
            .disconnect_context = options.disconnect_context,
            .tick_callback = options.tick_callback,
            .tick_context = options.tick_context,
        };
        server.resetRateLimiter();
        return server;
    }

    fn resetRateLimiter(self: *Self) void {
        self.rate_count = 0;
    }

    pub fn clampShardCount(requested: u8) usize {
        return @min(@max(@as(usize, requested), 1), ConnectionRegistryModule.MAX_SHARDS);
    }

    // Socket thread only: no locking.
    fn allowOfflinePacket(self: *Self, key: i64, now: Timestamp) bool {
        const now_ns: i64 = @intCast(now.nanoseconds);

        for (self.rate_entries[0..self.rate_count]) |*entry| {
            if (entry.key == key) {
                const elapsed_ns = now_ns - entry.last_ns;
                const refill: i64 = @divTrunc(elapsed_ns * RATE_TOKENS_PER_S, std.time.ns_per_s);
                entry.tokens = @min(RATE_CAPACITY_TOKENS, entry.tokens + @as(i32, @intCast(refill)));
                entry.last_ns = now_ns;
                if (entry.tokens <= 0) return false;
                entry.tokens -= 1;
                return true;
            }
        }

        if (self.rate_count < MAX_RATE_TRACKED) {
            self.rate_entries[self.rate_count] = .{ .key = key, .tokens = RATE_CAPACITY_TOKENS - 1, .last_ns = now_ns };
            self.rate_count += 1;
            return true;
        }

        // Table full: evict the entry with the fewest tokens.
        var victim: usize = 0;
        for (self.rate_entries[0..self.rate_count], 0..) |*entry, i| {
            if (entry.tokens < self.rate_entries[victim].tokens) victim = i;
        }
        self.rate_entries[victim] = .{ .key = key, .tokens = RATE_CAPACITY_TOKENS - 1, .last_ns = now_ns };
        return true;
    }

    fn tickLoop(self: *Self) void {
        const tick_interval = Duration.fromNanoseconds(
            @divTrunc(std.time.ns_per_s, @as(i96, self.options.tick_rate)),
        );

        var next_tick_deadline = Timestamp.now(self.io, .awake).addDuration(tick_interval);

        while (self.running.load(.acquire)) {
            waitUntil(self.io, next_tick_deadline);
            if (!self.running.load(.acquire)) break;

            const tick_start = Timestamp.now(self.io, .awake);
            next_tick_deadline = advanceTickDeadline(next_tick_deadline, tick_start, tick_interval);

            self.runConnectionPass();

            // After the barrier, on the tick thread, and unlocked: disconnect
            // callbacks touch game state and may re-enter the Server.
            self.drainRetired();

            const after_connections = Timestamp.now(self.io, .awake);
            self.last_connection_tick_ns = tick_start.durationTo(after_connections);

            if (self.tick_callback) |cb| cb(self.tick_context);

            const after_callback = Timestamp.now(self.io, .awake);
            self.last_total_tick_ns = tick_start.durationTo(after_callback);
            self.last_callback_tick_ns = after_connections.durationTo(after_callback);
        }
    }

    /// A single shard runs inline; otherwise wakes the shard owners and waits
    /// for the barrier.
    fn runConnectionPass(self: *Self) void {
        const pass: u64 = self.registry.pass_counter.fetchAdd(1, .monotonic) + 1;

        if (self.registry.shardCount() == 1) {
            self.runShardPass(0, pass);
        } else {
            self.registry.requestPasses(self.io, pass);
            self.registry.waitPasses(pass);
        }
    }

    fn runShardPass(self: *Self, index: usize, pass: u64) void {
        const io = self.io;
        const shard = &self.registry.shards[index];

        // Tick outside the lock so the socket handler keeps serving datagrams.
        {
            const token = self.registry.lockShard(io, index);
            defer self.registry.unlock(io, token);
            shard.snapshot.clearRetainingCapacity();
            shard.snapshot.appendSlice(self.options.allocator, shard.members.items) catch {};
        }

        for (shard.snapshot.items) |conn| {
            conn.tick();
        }

        {
            const token = self.registry.lockShard(io, index);
            defer self.registry.unlock(io, token);
            _ = self.registry.collectRetiredLocked(token);
        }

        shard.done_pass.store(pass, .release);
    }

    fn shardLoop(self: *Self, index: usize) void {
        const io = self.io;
        const shard = &self.registry.shards[index];
        while (true) {
            shard.mutex.lockUncancelable(io);
            while (shard.requested_pass == shard.seen_pass and self.running.load(.acquire)) {
                shard.condition.waitUncancelable(io, &shard.mutex);
            }
            if (!self.running.load(.acquire)) {
                shard.mutex.unlock(io);
                return;
            }
            shard.seen_pass = shard.requested_pass;
            shard.mutex.unlock(io);

            self.runShardPass(index, shard.seen_pass);
        }
    }

    /// Single-shard mode spawns nothing. A spawn failure rolls back the
    /// threads already started.
    fn startShardWorkers(self: *Self) !void {
        const shard_count = self.registry.shardCount();
        if (shard_count <= 1) return;

        const workers = try self.options.allocator.alloc(std.Thread, shard_count);
        errdefer self.options.allocator.free(workers);
        var started: usize = 0;
        errdefer {
            self.running.store(false, .release);
            self.registry.broadcastStop(self.io);
            for (workers[0..started]) |thread| thread.join();
        }
        for (workers, 0..) |*worker, index| {
            worker.* = try std.Thread.spawn(.{}, shardLoop, .{ self, index });
            started += 1;
        }
        self.shard_workers = workers;
    }

    /// Runs on the tick thread: disconnect callbacks touch simulation state
    /// that only that thread owns.
    fn drainRetired(self: *Self) void {
        self.retired_scratch.clearRetainingCapacity();
        for (0..self.registry.shardCount()) |index| {
            _ = self.registry.drainGraveyard(self.io, index, &self.retired_scratch);
        }
        for (self.retired_scratch.items) |conn| {
            if (self.disconnect_callback) |callback| {
                callback(conn, self.disconnect_context);
            }
            conn.deinit();
            self.options.allocator.destroy(conn);
        }
        self.retired_scratch.clearRetainingCapacity();
    }

    fn advanceTickDeadline(
        current_deadline: Timestamp,
        tick_start: Timestamp,
        tick_interval: Duration,
    ) Timestamp {
        // Re-anchor after a long stall instead of looping over every missed tick.
        const missed = tick_start.nanoseconds - current_deadline.nanoseconds;
        if (missed > 64 * tick_interval.nanoseconds) {
            return tick_start.addDuration(tick_interval);
        }

        var next_deadline = current_deadline.addDuration(tick_interval);
        while (next_deadline.nanoseconds <= tick_start.nanoseconds) {
            next_deadline = next_deadline.addDuration(tick_interval);
        }
        return next_deadline;
    }

    fn waitUntil(io: std.Io, deadline: Timestamp) void {
        const coarse_sleep_guard_ns: u64 = if (is_windows) 2_000_000 else 500_000;
        const yield_guard_ns: u64 = if (is_windows) 200_000 else 100_000;

        while (true) {
            const now = Timestamp.now(io, .awake);
            const remaining = deadline.subDuration(Duration.fromNanoseconds(now.nanoseconds));
            if (remaining.toMilliseconds() <= 0) return;

            const remaining_ns: u64 = @intCast(remaining.nanoseconds);
            if (remaining_ns > coarse_sleep_guard_ns) {
                io.sleep(
                    Duration.fromNanoseconds(@intCast(remaining_ns - coarse_sleep_guard_ns)),
                    .awake,
                ) catch return;
                continue;
            }

            if (remaining_ns > yield_guard_ns) {
                std.Thread.yield() catch {};
            } else {
                std.atomic.spinLoopHint();
            }
        }
    }

    pub fn senderActive(self: *const Self) bool {
        return self.options.sender_threads > 0 and self.sender_thread != null;
    }

    /// With `output_slot` set, the queue retains the slot while in flight.
    /// Falls back to a direct send if the ring or pool is exhausted.
    pub fn submitDatagram(self: *Self, to: std.Io.net.IpAddress, bytes: []const u8, output_slot: ?u32) void {
        if (!self.senderActive()) {
            self.sendNow(to, bytes);
            return;
        }

        if (output_slot) |slot| {
            self.output_slab.retain(slot);
            if (self.outbound.enqueue(.{ .to = to, .bytes = bytes, .release = .{ .slab_slot = slot } })) {
                return;
            }
            self.output_slab.release(slot);
            self.sendNow(to, bytes);
            return;
        }

        self.submitTransient(to, bytes);
    }

    /// Copies `bytes` into the transient pool before queueing.
    pub fn submitTransient(self: *Self, to: std.Io.net.IpAddress, bytes: []const u8) void {
        if (!self.senderActive()) {
            self.sendNow(to, bytes);
            return;
        }

        if (self.transient_slab.claim()) |slot| {
            const buffer = self.transient_slab.slotBytes(slot);
            if (bytes.len <= buffer.len) {
                @memcpy(buffer[0..bytes.len], bytes);
                if (self.outbound.enqueue(.{ .to = to, .bytes = buffer[0..bytes.len], .release = .{ .transient_slot = slot } })) {
                    return;
                }
            }
            self.transient_slab.release(slot);
        }

        self.sendNow(to, bytes);
    }

    fn releaseDatagram(self: *Self, datagram: OutboundDatagram) void {
        switch (datagram.release) {
            .none => {},
            .slab_slot => |slot| self.output_slab.release(slot),
            .transient_slot => |slot| self.transient_slab.release(slot),
        }
    }

    fn sendNow(self: *Self, to: std.Io.net.IpAddress, data: []const u8) void {
        self.socket.send(data, to) catch |err| {
            Logger.ERROR("Failed to send: {s}", .{@errorName(err)});
        };
    }

    /// Single FIFO consumer of the ring; this preserves per-connection order.
    fn senderLoop(self: *Self) void {
        while (self.running.load(.acquire)) {
            var sent: usize = 0;
            while (sent < SENDER_MAX_BATCH) {
                const datagram = self.outbound.dequeue() orelse break;
                self.socket.send(datagram.bytes, datagram.to) catch |err| {
                    Logger.ERROR("Failed to send: {s}", .{@errorName(err)});
                };
                self.releaseDatagram(datagram);
                sent += 1;
            }
            if (sent == 0) {
                self.io.sleep(.fromNanoseconds(SENDER_IDLE_SLEEP_NS), .awake) catch {};
            }
        }
    }

    pub fn start(self: *Self) !void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.io, .awake) else null;

        Logger.INFO("Starting server on {s}:{d}", .{ self.options.address, self.options.port });
        self.resetRateLimiter();
        self.running.store(true, .release);
        try self.startShardWorkers();
        self.tick_thread = try self.io.concurrent(tickLoop, .{self});

        var seed: u64 = undefined;
        self.io.random(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);

        self.options.advertisement.guid = prng.random().int(i64);
        self.socket.setCallback(packet_callback, self);

        try self.socket.listen();

        if (self.options.sender_threads > 0) {
            self.sender_thread = std.Thread.spawn(.{}, senderLoop, .{self}) catch |err| blk: {
                Logger.ERROR("Failed to spawn outbound sender thread: {s}", .{@errorName(err)});
                break :blk null;
            };
        }

        if (start_time) |s_time| {
            const elapsed = s_time.untilNow(self.io, .awake);
            Logger.DEBUG("PERF: server start took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn packet_callback(
        data: []const u8,
        from_addr: std.Io.net.IpAddress,
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
    ) void {
        const self = @as(*Self, @ptrCast(@alignCast(context)));
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.io, .awake) else null;

        if (data.len == 0) return;

        var ID: u8 = data[0];
        if (ID & 0xF0 == 0x80) ID = 0x80;
        const key = addressToKey(from_addr);

        switch (ID) {
            Packets.UnconnectedPing => {
                if (data.len < 33 or !std.mem.eql(u8, data[9..25], &Proto.Magic.bytes)) return;
                if (!self.allowOfflinePacket(key, Timestamp.now(self.io, .awake))) return;

                const string = self.options.advertisement.toString(self.options.allocator);
                defer self.options.allocator.free(string);

                var pong_buf: [1024]u8 = undefined;
                var pong = Proto.UnconnectedPong.init(
                    Timestamp.now(self.io, .real).toMilliseconds(),
                    self.options.advertisement.guid,
                    string,
                );

                defer pong.deinit(allocator);
                const pong_data = Proto.UnconnectedPong.serializeInto(&pong, &pong_buf) catch |err| {
                    Logger.ERROR("Failed to serialize unconnected pong: {s}", .{@errorName(err)});
                    return;
                };

                self.send(pong_data, from_addr);
            },
            Packets.OpenConnectionRequest1 => {
                if (data.len < 18 or !std.mem.eql(u8, data[1..17], &Proto.Magic.bytes)) return;
                if (!self.allowOfflinePacket(key, Timestamp.now(self.io, .awake))) return;

                var reply = Proto.ConnectionReply1.init(
                    self.options.advertisement.guid,
                    false,
                    self.options.max_mtu,
                );

                defer reply.deinit();

                var reply_buf: [Proto.ConnectionReply1.MAX_SERIALIZED_SIZE]u8 = undefined;
                const reply_data = reply.serializeInto(&reply_buf) catch |err| {
                    Logger.ERROR("Failed to serialize connection reply 1: {s}", .{@errorName(err)});
                    return;
                };

                self.send(reply_data, from_addr);
            },
            Packets.OpenConnectionRequest2 => {
                if (!self.allowOfflinePacket(key, Timestamp.now(self.io, .awake))) return;

                var request = Proto.ConnectionRequest2.deserialize(data, self.options.allocator) catch |err| {
                    Logger.ERROR("Failed to deserialize connection request 2: {s}", .{@errorName(err)});
                    return;
                };

                defer request.deinit(allocator);

                const mtu = @min(request.mtu_size, self.options.max_mtu);
                const address = Proto.Address.init(4, "0.0.0.0", 0);

                var reply = Proto.ConnectionReply2.init(
                    self.options.advertisement.guid,
                    address,
                    mtu,
                    false,
                );

                defer reply.deinit(allocator);

                var reply_buf: [Proto.ConnectionReply2.MAX_SERIALIZED_SIZE]u8 = undefined;
                const reply_data = reply.serializeInto(&reply_buf) catch |err| {
                    Logger.ERROR("Failed to serialize connection reply 2: {s}", .{@errorName(err)});
                    return;
                };

                self.send(reply_data, from_addr);

                const token = self.registry.lock(self.io, key);
                defer self.registry.unlock(self.io, token);

                if (ConnectionRegistry.getLocked(token, key) != null) {
                    // Retransmitted handshake: the reply above is enough.
                } else {
                    const conn = self.options.allocator.create(Connection) catch |err| {
                        Logger.ERROR("Failed to allocate connection: {s}", .{@errorName(err)});
                        return;
                    };

                    conn.* = Connection.init(self, from_addr, mtu, request.guid);

                    self.registry.putLocked(token, conn) catch |err| {
                        Logger.ERROR("Failed to add connection to shard: {s}", .{@errorName(err)});
                        conn.deinit();
                        self.options.allocator.destroy(conn);
                        return;
                    };
                }
            },
            Packets.FrameSet => {
                var connect_event: ?*Connection = null;

                // Held for the whole datagram so a retirement cannot free the
                // connection mid-handling.
                {
                    const token = self.registry.lock(self.io, key);
                    defer self.registry.unlock(self.io, token);

                    if (ConnectionRegistry.getLocked(token, key)) |conn| {
                        if (!conn.isActive()) return;
                        conn.onFrameSet(data) catch |err| {
                            Logger.ERROR("Failed to handle frame set: {s}", .{@errorName(err)});
                            return;
                        };
                        if (conn.takePendingConnect()) connect_event = conn;
                    }
                }

                // Fires after unlock.
                if (connect_event) |conn| {
                    if (self.connect_callback) |callback| {
                        callback(conn, self.connect_context);
                    }
                }
            },
            Packets.Ack => {
                const token = self.registry.lock(self.io, key);
                defer self.registry.unlock(self.io, token);

                if (ConnectionRegistry.getLocked(token, key)) |conn| {
                    if (!conn.isActive()) return;
                    conn.handleAck(data) catch |err| {
                        Logger.ERROR("Failed to handle ack: {s}", .{@errorName(err)});
                        return;
                    };
                }
            },
            Packets.Nack => {
                const token = self.registry.lock(self.io, key);
                defer self.registry.unlock(self.io, token);

                if (ConnectionRegistry.getLocked(token, key)) |conn| {
                    if (!conn.isActive()) return;
                    conn.handleNack(data) catch |err| {
                        Logger.ERROR("Failed to handle nack: {s}", .{@errorName(err)});
                        return;
                    };
                }
            },
            else => {
                Logger.WARN("Unknown ID {d}", .{ID});
                const token = self.registry.lock(self.io, key);
                defer self.registry.unlock(self.io, token);
                if (ConnectionRegistry.getLocked(token, key) != null) {
                    Logger.DEBUG("Connection already exists", .{});
                }
            },
        }

        if (start_time) |s_time| {
            const elapsed = s_time.untilNow(self.io, .awake);
            Logger.DEBUG("PERF: packet_callback took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn send(self: *Self, data: []const u8, to_addr: std.Io.net.IpAddress) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.io, .awake) else null;

        self.sendNow(to_addr, data);

        if (start_time) |s_start| {
            const elapsed = s_start.untilNow(self.io, .awake);
            Logger.DEBUG("PERF: send took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn disconnect(self: *Self, address: std.Io.net.IpAddress) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.io, .awake) else null;

        const key = addressToKey(address);
        Logger.INFO("Disconnecting connection with key: {d}", .{key});

        const dc = [_]u8{Packets.DisconnectNotification};
        self.send(&dc, address);

        const token = self.registry.lock(self.io, key);
        defer self.registry.unlock(self.io, token);

        if (ConnectionRegistry.getLocked(token, key)) |conn| {
            conn.deactivate();
            conn.connected.store(false, .release);
        } else {
            Logger.WARN("Attempted to disconnect non-existent connection: {d}", .{key});
        }

        if (start_time) |s_time| {
            const elapsed = s_time.untilNow(self.io, .awake);
            Logger.DEBUG("PERF: disconnect took {d} ms", .{elapsed.toMilliseconds()});
        }
    }

    pub fn setConnectCallback(self: *Self, callback: ?ConnectCallback, context: ?*anyopaque) void {
        self.connect_callback = callback;
        self.connect_context = context;
    }

    pub fn setDisconnectCallback(self: *Self, callback: ?DisconnectCallback, context: ?*anyopaque) void {
        self.disconnect_callback = callback;
        self.disconnect_context = context;
    }

    pub fn setTickCallback(self: *Self, callback: ?TickCallback, context: ?*anyopaque) void {
        self.tick_callback = callback;
        self.tick_context = context;
    }

    /// The pointer may be retired on the next pass; re-check `isActive()`.
    pub fn getConnection(self: *Self, address: std.Io.net.IpAddress) ?*Connection {
        const key = addressToKey(address);
        const token = self.registry.lock(self.io, key);
        defer self.registry.unlock(self.io, token);
        return ConnectionRegistry.getLocked(token, key);
    }

    pub fn getActiveConnections(self: *Self, allocator: std.mem.Allocator) !std.ArrayList(*Connection) {
        var active_connections = std.ArrayList(*Connection).empty;

        for (0..self.registry.shardCount()) |index| {
            const token = self.registry.lockShard(self.io, index);
            defer self.registry.unlock(self.io, token);

            var iterator = token.shard.connections.valueIterator();
            while (iterator.next()) |entry| {
                if (entry.*.isActive()) {
                    try active_connections.append(allocator, entry.*);
                }
            }
        }

        return active_connections;
    }

    pub fn deinit(self: *Self) void {
        const start_time: ?Timestamp = if (PERFORM_TIME_CHECKS) .now(self.io, .awake) else null;

        // Stop every producer before touching the table.
        self.running.store(false, .release);
        self.registry.broadcastStop(self.io);
        if (self.sender_thread) |thread| {
            thread.join();
            self.sender_thread = null;
        }
        if (self.tick_thread) |*thread| {
            _ = thread.cancel(self.io);
            self.tick_thread = null;
        }
        for (self.shard_workers) |thread| thread.join();
        if (self.shard_workers.len > 0) self.options.allocator.free(self.shard_workers);
        self.shard_workers = &.{};

        self.socket.stop();

        for (self.registry.shards) |*shard| {
            for (shard.members.items) |conn| {
                conn.deinit();
                self.options.allocator.destroy(conn);
            }
            for (shard.graveyard.items) |conn| {
                conn.deinit();
                self.options.allocator.destroy(conn);
            }
            shard.members.clearRetainingCapacity();
            shard.graveyard.clearRetainingCapacity();
        }
        self.registry.deinit();
        self.retired_scratch.deinit(self.options.allocator);

        // Connections released their slab slots above.
        self.output_slab.deinit(self.options.allocator);
        self.transient_slab.deinit(self.options.allocator);
        self.outbound.deinit(self.options.allocator);

        self.socket.deinit();

        if (start_time) |s_time| {
            const elapsed = s_time.untilNow(self.io, .awake);
            Logger.DEBUG("PERF: deinit took {d} ms", .{elapsed.toMilliseconds()});
        }
    }
};

pub const ServerOptions = struct {
    address: []const u8 = "0.0.0.0",
    port: u16 = 19132,
    max_mtu: u16 = 1400,
    allocator: std.mem.Allocator = std.heap.page_allocator,
    tick_rate: u16 = 20,
    /// Allocation-free output path; disable to restore the copying path.
    output_arena: bool = true,
    /// 0 = default.
    output_slab_slots: u32 = OUTPUT_SLOT_COUNT,
    /// Dedicated sender threads that own `sendto`; 0 sends on the producer
    /// thread. One is enough and keeps per-connection order.
    sender_threads: u8 = 0,
    /// Connection-table shards, each with its own maintenance thread. 1 runs
    /// the pass inline on the tick thread. Clamped to 1..8.
    shards: u8 = DEFAULT_SHARDS,
    /// Ring size before falling back to a direct send (0 = default).
    outbound_queue_slots: usize = OUTBOUND_QUEUE_SLOTS,
    /// 0 = default.
    transient_slab_slots: u32 = TRANSIENT_SLOT_COUNT,
    advertisement: Proto.Advertisement = Proto.Advertisement.init(
        .MCPE,
        "Conduit Server",
        800,
        "1.21.80",
        0,
        10,
        0,
        "Conduit Server",
        "Survival",
    ),
    connect_callback: ?ConnectCallback = null,
    connect_context: ?*anyopaque = null,
    disconnect_callback: ?DisconnectCallback = null,
    disconnect_context: ?*anyopaque = null,
    tick_callback: ?TickCallback = null,
    tick_context: ?*anyopaque = null,
};

test "addressToKey IPv4 produces unique keys" {
    const addr1: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19132 } };
    const addr2: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 19133 } };
    const addr3: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 168, 1, 1 }, .port = 19132 } };

    const key1 = Server.addressToKey(addr1);
    const key2 = Server.addressToKey(addr2);
    const key3 = Server.addressToKey(addr3);

    try std.testing.expect(key1 != key2);
    try std.testing.expect(key1 != key3);
    try std.testing.expectEqual(key1, Server.addressToKey(addr1));
}

test "addressToKey IPv6 produces unique keys" {
    const addr1: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 19132 } };
    const addr2: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 19133 } };
    const addr3: std.Io.net.IpAddress = .{ .ip6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 }, .port = 19132 } };

    const key1 = Server.addressToKey(addr1);
    const key2 = Server.addressToKey(addr2);
    const key3 = Server.addressToKey(addr3);

    try std.testing.expect(key1 != key2);
    try std.testing.expect(key1 != key3);
    try std.testing.expectEqual(key1, Server.addressToKey(addr1));
}

test "Server init and deinit" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{
        .allocator = allocator,
        .port = 0,
    });
    defer server.deinit();

    try std.testing.expect(!server.running.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), server.registry.shards[0].connections.count());
    try std.testing.expectEqual(Server.clampShardCount(0), @as(usize, 1));
    try std.testing.expectEqual(Server.clampShardCount(4), @as(usize, 4));
    try std.testing.expectEqual(Server.clampShardCount(200), ConnectionRegistryModule.MAX_SHARDS);
}

fn testConnection(server: *Server, allocator: std.mem.Allocator) !*Connection {
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } };
    const conn = try allocator.create(Connection);
    conn.* = Connection.init(server, address, 1400, 0);
    conn.active.store(true, .release);
    return conn;
}

fn ackSequences(conn: *Connection, sequences: []const u32) !void {
    var ack_buf: [64]u8 = undefined;
    const ack_bytes = try Proto.Ack.serializeInto(sequences, Proto.Packets.Ack, &ack_buf);
    try conn.handleAck(ack_bytes);
}

test "the output slab backs up framesets and recycles on ACK" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .output_slab_slots = 4 });
    defer server.deinit();

    const conn = try testConnection(&server, allocator);
    defer {
        conn.deinit();
        allocator.destroy(conn);
    }

    const owned = try allocator.dupe(u8, "owned payload");
    conn.sendReliableMessageOwned(owned, .Immediate);
    try std.testing.expectEqual(@as(usize, 3), server.output_slab.available());

    const sequence = conn.comm_data.output_sequence - 1;
    try ackSequences(conn, &[_]u32{sequence});
    try std.testing.expectEqual(@as(usize, 4), server.output_slab.available());

    const packets = [_][]const u8{ "aa", "bbbb", "cccccc" };
    conn.sendPacketBatch(&packets, .Immediate);
    try std.testing.expectEqual(@as(usize, 3), server.output_slab.available());
    try ackSequences(conn, &[_]u32{conn.comm_data.output_sequence - 1});
    try std.testing.expectEqual(@as(usize, 4), server.output_slab.available());
}

test "a large owned message is split across slab-backed framesets" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .output_slab_slots = 8 });
    defer server.deinit();

    const conn = try testConnection(&server, allocator);
    defer {
        conn.deinit();
        allocator.destroy(conn);
    }

    // 4000 bytes with a 1400 MTU splits into three fragments.
    const big = try allocator.dupe(u8, "x" ** 4000);
    conn.sendReliableMessageOwned(big, .Immediate);

    try std.testing.expectEqual(@as(usize, 5), server.output_slab.available());

    const first = conn.comm_data.output_sequence - 3;
    try ackSequences(conn, &[_]u32{ first, first + 1, first + 2 });
    try std.testing.expectEqual(@as(usize, 8), server.output_slab.available());
}

test "with the output arena off the legacy path sends and ACKs" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .output_arena = false });
    defer server.deinit();

    const conn = try testConnection(&server, allocator);
    defer {
        conn.deinit();
        allocator.destroy(conn);
    }

    conn.sendReliableMessageOwned(try allocator.dupe(u8, "legacy payload"), .Immediate);

    const sequence = conn.comm_data.output_sequence - 1;
    try ackSequences(conn, &[_]u32{sequence});
}

test "advanceTickDeadline keeps fixed cadence after a late wake" {
    const tick_interval: Duration = .fromNanoseconds(50_000_000);
    const previous_deadline: Timestamp = .fromNanoseconds(1_000_000_000);
    const late_tick_start: Timestamp = previous_deadline.addDuration(.fromNanoseconds(12_000_000));

    try std.testing.expectEqual(
        previous_deadline.addDuration(tick_interval),
        Server.advanceTickDeadline(previous_deadline, late_tick_start, tick_interval),
    );
}

test "advanceTickDeadline skips missed intervals when badly behind" {
    const tick_interval: Duration = .fromNanoseconds(50_000_000);
    const previous_deadline: Timestamp = .fromNanoseconds(1_000_000_000);
    const late_tick_start: Timestamp = previous_deadline.addDuration(.fromNanoseconds(125_000_000));

    try std.testing.expectEqual(
        previous_deadline.addDuration(.fromNanoseconds(3 * 50_000_000)),
        Server.advanceTickDeadline(previous_deadline, late_tick_start, tick_interval),
    );
}

test "advanceTickDeadline re-anchors after a long stall" {
    const tick_interval: Duration = .fromNanoseconds(50_000_000);
    const previous_deadline: Timestamp = .fromNanoseconds(1_000_000_000);
    const stalled_tick_start: Timestamp = previous_deadline.addDuration(.fromNanoseconds(3_600 * std.time.ns_per_s));

    try std.testing.expectEqual(
        stalled_tick_start.addDuration(tick_interval),
        Server.advanceTickDeadline(previous_deadline, stalled_tick_start, tick_interval),
    );
}

fn waitForRingEmpty(server: *Server) !void {
    var attempts: usize = 0;
    while (server.outbound.depth() != 0 and attempts < 2000) : (attempts += 1) {
        std.testing.io.sleep(.fromNanoseconds(100_000), .awake) catch {};
    }
    try std.testing.expectEqual(@as(usize, 0), server.outbound.depth());
}

/// The sender releases slots asynchronously, so poll the pool.
fn waitForSlots(slab: *OutputSlab, target: usize) !void {
    var attempts: usize = 0;
    while (slab.available() != target and attempts < 2000) : (attempts += 1) {
        std.testing.io.sleep(.fromNanoseconds(100_000), .awake) catch {};
    }
    try std.testing.expectEqual(target, slab.available());
}

/// Keeps `senderActive()` true without draining the ring.
const PausedSender = struct {
    stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    fn run(self: *PausedSender) void {
        while (!self.stop.load(.acquire)) {
            std.testing.io.sleep(.fromNanoseconds(100_000), .awake) catch {};
        }
    }

    fn start(self: *PausedSender, server: *Server) !void {
        self.thread = try std.Thread.spawn(.{}, run, .{self});
        server.sender_thread = self.thread;
    }

    fn stopAndJoin(self: *PausedSender, server: *Server) void {
        self.stop.store(true, .release);
        if (self.thread) |thread| thread.join();
        self.thread = null;
        server.sender_thread = null;
    }
};

test "the outbound sender drains the ring and releases pooled slots" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{
        .allocator = allocator,
        .port = 0,
        .sender_threads = 1,
        .output_slab_slots = 4,
        .transient_slab_slots = 4,
        .outbound_queue_slots = 8,
    });
    defer server.deinit();
    // Spawned without `start()`: tests don't initialize the logger.
    server.running.store(true, .release);
    server.sender_thread = try std.Thread.spawn(.{}, Server.senderLoop, .{&server});

    const conn = try testConnection(&server, allocator);
    defer {
        conn.deinit();
        allocator.destroy(conn);
    }

    const payload = try allocator.dupe(u8, "sender payload");
    conn.sendReliableMessageOwned(payload, .Immediate);
    try std.testing.expectEqual(@as(usize, 3), server.output_slab.available());

    try waitForRingEmpty(&server);
    // The backup keeps the slot until the ACK arrives.
    try std.testing.expectEqual(@as(usize, 3), server.output_slab.available());
    try ackSequences(conn, &[_]u32{conn.comm_data.output_sequence - 1});
    try waitForSlots(&server.output_slab, 4);

    server.submitTransient(conn.address, "ack bytes");
    try waitForSlots(&server.transient_slab, 4);
}

test "a full outbound ring falls back to a direct send without dropping the datagram" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{
        .allocator = allocator,
        .port = 0,
        .sender_threads = 1,
        .transient_slab_slots = 4,
        .outbound_queue_slots = 2,
    });
    defer server.deinit();

    var paused = PausedSender{};
    try paused.start(&server);
    defer paused.stopAndJoin(&server);

    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 1 } };
    const padding = [_]u8{'x'} ** 8;
    try std.testing.expect(server.outbound.enqueue(.{ .to = address, .bytes = &padding }));
    try std.testing.expect(server.outbound.enqueue(.{ .to = address, .bytes = &padding }));

    server.submitDatagram(address, "overflowing datagram", null);
    try std.testing.expectEqual(@as(usize, 2), server.outbound.depth());
    try std.testing.expectEqual(@as(usize, 4), server.transient_slab.available());
}

test "connection teardown cannot recycle slots the sender is still reading" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{
        .allocator = allocator,
        .port = 0,
        .sender_threads = 1,
        .output_slab_slots = 4,
        .transient_slab_slots = 4,
        .outbound_queue_slots = 16,
    });
    defer server.deinit();

    var paused = PausedSender{};
    try paused.start(&server);
    defer paused.stopAndJoin(&server);

    const conn = try testConnection(&server, allocator);
    for (0..3) |_| {
        conn.sendReliableMessageOwned(try allocator.dupe(u8, "in flight"), .Immediate);
    }
    try std.testing.expectEqual(@as(usize, 1), server.output_slab.available());

    // The ring's references keep the slots alive after teardown.
    conn.deinit();
    allocator.destroy(conn);
    try std.testing.expectEqual(@as(usize, 1), server.output_slab.available());

    while (server.outbound.dequeue()) |datagram| server.releaseDatagram(datagram);
    try std.testing.expectEqual(@as(usize, 4), server.output_slab.available());
}

/// The byte is used in first and last position to be endianness agnostic, so
/// distinct bytes give distinct keys and shards.
fn testConnectionAt(server: *Server, allocator: std.mem.Allocator, ip_byte: u8, port: u16) !*Connection {
    const address: std.Io.net.IpAddress = .{ .ip4 = .{ .bytes = .{ ip_byte, 0, 0, ip_byte }, .port = port } };
    const conn = try allocator.create(Connection);
    conn.* = Connection.init(server, address, 1400, 0);
    conn.active.store(true, .release);
    return conn;
}

fn registerTestConnection(server: *Server, io: std.Io, conn: *Connection) !void {
    const token = server.registry.lock(io, conn.key);
    defer server.registry.unlock(io, token);
    try server.registry.putLocked(token, conn);
}

const DisconnectCounter = struct { count: usize = 0 };

fn countDisconnect(connection: *Connection, context: ?*anyopaque) void {
    _ = connection;
    const counter: *DisconnectCounter = @ptrCast(@alignCast(context.?));
    counter.count += 1;
}

test "connection keys map to stable, spread shards" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .shards = 4 });
    defer server.deinit();

    const key = Server.addressToKey(.{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = 19132 } });
    try std.testing.expectEqual(server.registry.shardIndex(key), server.registry.shardIndex(key));

    // Keys that differ only in the port bits must still spread over the shards.
    var seen: [4]bool = .{ false, false, false, false };
    for (1..33) |port| {
        const probe = Server.addressToKey(.{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = @intCast(port) } });
        const index = server.registry.shardIndex(probe);
        try std.testing.expect(index < seen.len);
        seen[index] = true;
    }
    var distinct: usize = 0;
    for (seen) |hit| {
        if (hit) distinct += 1;
    }
    try std.testing.expectEqual(@as(usize, 4), distinct);
}

test "shard workers run the maintenance pass behind a per-tick barrier" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .shards = 2, .output_slab_slots = 8 });
    defer server.deinit();
    server.running.store(true, .release);
    try server.startShardWorkers();

    var disconnected = DisconnectCounter{};
    server.setDisconnectCallback(countDisconnect, &disconnected);

    const first = try testConnectionAt(&server, allocator, 1, 100);
    const second = try testConnectionAt(&server, allocator, 2, 200);
    try std.testing.expect(server.registry.shardIndex(first.key) != server.registry.shardIndex(second.key));
    try registerTestConnection(&server, io, first);
    try registerTestConnection(&server, io, second);

    // Queued frames are only flushed by the pass.
    first.sendReliableMessage("queued", .Normal);
    try std.testing.expectEqual(@as(usize, 8), server.output_slab.available());

    server.runConnectionPass();
    try std.testing.expectEqual(@as(usize, 7), server.output_slab.available());

    const second_key = second.key;
    second.deactivate();
    server.runConnectionPass();
    server.drainRetired();
    try std.testing.expectEqual(@as(usize, 1), disconnected.count);
    {
        const token = server.registry.lock(io, second_key);
        defer server.registry.unlock(io, token);
        try std.testing.expect(ConnectionRegistry.getLocked(token, second_key) == null);
    }
    // `first` stays registered: Server.deinit destroys it.
}

test "concurrent socket handling cannot race a retirement pass" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var server = try Server.init(io, .{ .allocator = allocator, .port = 0, .shards = 1 });
    defer server.deinit();
    server.running.store(true, .release);

    var disconnected = DisconnectCounter{};
    server.setDisconnectCallback(countDisconnect, &disconnected);

    const conn = try testConnectionAt(&server, allocator, 1, 1);
    try registerTestConnection(&server, io, conn);

    var ack_buf: [64]u8 = undefined;
    const ack_bytes = try Proto.Ack.serializeInto(&[_]u32{ 1, 2, 3 }, Proto.Packets.Ack, &ack_buf);

    const Producer = struct {
        server: *Server,
        key: i64,
        ack_bytes: []const u8,
        stop: *std.atomic.Value(bool),

        fn run(self: @This()) void {
            while (!self.stop.load(.acquire)) {
                const token = self.server.registry.lock(std.testing.io, self.key);
                defer self.server.registry.unlock(std.testing.io, token);
                if (ConnectionRegistry.getLocked(token, self.key)) |target| {
                    if (!target.isActive()) continue;
                    target.handleAck(self.ack_bytes) catch {};
                }
            }
        }
    };

    var stop = std.atomic.Value(bool).init(false);
    const producer = try std.Thread.spawn(.{}, Producer.run, .{Producer{
        .server = &server,
        .key = conn.key,
        .ack_bytes = ack_bytes,
        .stop = &stop,
    }});

    for (0..16) |_| {
        server.runConnectionPass();
    }
    conn.deactivate();
    server.runConnectionPass();
    server.drainRetired();

    stop.store(true, .release);
    producer.join();
    try std.testing.expectEqual(@as(usize, 1), disconnected.count);
}
