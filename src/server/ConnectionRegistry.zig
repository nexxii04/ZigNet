const std = @import("std");
const Mutex = std.Io.Mutex;
const Condition = std.Io.Condition;

const Connection = @import("./Connection.zig").Connection;

pub const MAX_SHARDS: usize = 8;

/// One shard of the connection table.
///
/// - `connections`, `members` and `graveyard` mutate only under `mutex`.
/// - The owner thread snapshots `members` under the mutex and ticks outside
///   it; the socket thread holds the mutex while handling a datagram, so a
///   teardown cannot free a connection in use.
/// - The tick thread bumps `requested_pass` and signals `condition`; the owner
///   publishes `done_pass` (release) when its pass ends.
pub const Shard = struct {
    mutex: Mutex = .init,
    connections: std.AutoHashMap(i64, *Connection),
    members: std.ArrayList(*Connection) = .empty,
    /// Inactive connections waiting for the tick thread to destroy them.
    graveyard: std.ArrayList(*Connection) = .empty,
    /// Reused copy of `members`, owned by the shard worker.
    snapshot: std.ArrayList(*Connection) = .empty,

    condition: Condition = .init,
    requested_pass: u64 = 0,
    seen_pass: u64 = 0,
    done_pass: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub const LockToken = struct {
    shard: *Shard,
};

/// Sharded connection table: one map and one mutex per shard.
pub const ConnectionRegistry = struct {
    shards: []Shard,
    allocator: std.mem.Allocator,
    pass_counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    retired: std.ArrayList(*Connection) = .empty,

    pub fn init(allocator: std.mem.Allocator, shard_count: usize) !ConnectionRegistry {
        const count = @min(@max(shard_count, 1), MAX_SHARDS);
        const shards = try allocator.alloc(Shard, count);
        errdefer allocator.free(shards);
        for (shards) |*shard_ptr| {
            shard_ptr.* = .{ .connections = std.AutoHashMap(i64, *Connection).init(allocator) };
            shard_ptr.members.ensureTotalCapacity(allocator, 64) catch {};
            shard_ptr.snapshot.ensureTotalCapacity(allocator, 64) catch {};
            shard_ptr.graveyard.ensureTotalCapacity(allocator, 16) catch {};
        }
        return .{ .shards = shards, .allocator = allocator };
    }

    pub fn deinit(self: *ConnectionRegistry) void {
        for (self.shards) |*shard_ptr| {
            shard_ptr.connections.deinit();
            shard_ptr.members.deinit(self.allocator);
            shard_ptr.graveyard.deinit(self.allocator);
            shard_ptr.snapshot.deinit(self.allocator);
        }
        self.allocator.free(self.shards);
        self.shards = &.{};
        self.retired.deinit(self.allocator);
    }

    pub fn shardCount(self: *const ConnectionRegistry) usize {
        return self.shards.len;
    }

    /// splitmix64 finalizer: keys of clients behind one NAT differ only in
    /// the port bits, so a raw modulo would pile them onto one shard.
    pub fn shardIndex(self: *const ConnectionRegistry, key: i64) usize {
        var bits: u64 = @bitCast(key);
        bits ^= bits >> 30;
        bits *%= 0xbf58476d1ce4e5b9;
        bits ^= bits >> 27;
        bits *%= 0x94d049bb133111eb;
        bits ^= bits >> 31;
        return @intCast(bits % self.shards.len);
    }

    pub fn lock(self: *ConnectionRegistry, io: std.Io, key: i64) LockToken {
        const index = self.shardIndex(key);
        const shard_ptr = &self.shards[index];
        shard_ptr.mutex.lockUncancelable(io);
        return .{ .shard = shard_ptr };
    }

    pub fn unlock(_: *ConnectionRegistry, io: std.Io, token: LockToken) void {
        token.shard.mutex.unlock(io);
    }

    pub fn putLocked(self: *ConnectionRegistry, token: LockToken, conn: *Connection) !void {
        const shard_ptr = token.shard;
        try shard_ptr.connections.put(conn.key, conn);
        errdefer _ = shard_ptr.connections.remove(conn.key);
        try shard_ptr.members.append(self.allocator, conn);
    }

    pub fn getLocked(token: LockToken, key: i64) ?*Connection {
        return token.shard.connections.get(key);
    }

    /// Moves inactive members to the graveyard and returns how many.
    /// The map entry is dropped only after the graveyard owns the connection,
    /// so a racing lookup either finds it inactive or misses it.
    pub fn collectRetiredLocked(self: *ConnectionRegistry, token: LockToken) usize {
        const shard_ptr = token.shard;
        var retired: usize = 0;
        var index: usize = 0;
        while (index < shard_ptr.members.items.len) {
            const conn = shard_ptr.members.items[index];
            if (conn.isActive()) {
                index += 1;
                continue;
            }
            if (shard_ptr.graveyard.items.len >= shard_ptr.graveyard.capacity) {
                shard_ptr.graveyard.ensureUnusedCapacity(self.allocator, 8) catch break;
            }
            shard_ptr.graveyard.appendAssumeCapacity(conn);
            _ = shard_ptr.members.swapRemove(index);
            _ = shard_ptr.connections.remove(conn.key);
            retired += 1;
        }
        return retired;
    }

    pub fn drainGraveyard(self: *ConnectionRegistry, io: std.Io, index: usize, out: *std.ArrayList(*Connection)) usize {
        const shard_ptr = &self.shards[index];
        const token = self.lockShard(io, index);
        defer self.unlock(io, token);

        out.appendSlice(self.allocator, shard_ptr.graveyard.items) catch {
            // Keep the batch for the next tick instead of losing it.
            return 0;
        };
        const drained = shard_ptr.graveyard.items.len;
        shard_ptr.graveyard.clearRetainingCapacity();
        return drained;
    }

    pub fn lockShard(self: *ConnectionRegistry, io: std.Io, index: usize) LockToken {
        const shard_ptr = &self.shards[index];
        shard_ptr.mutex.lockUncancelable(io);
        return .{ .shard = shard_ptr };
    }

    pub fn requestPasses(self: *ConnectionRegistry, io: std.Io, pass: u64) void {
        for (self.shards) |*shard_ptr| {
            shard_ptr.mutex.lockUncancelable(io);
            shard_ptr.requested_pass = pass;
            shard_ptr.condition.signal(io);
            shard_ptr.mutex.unlock(io);
        }
    }

    /// Spins, then yields, until every owner has published `pass`.
    pub fn waitPasses(self: *ConnectionRegistry, pass: u64) void {
        for (self.shards) |*shard_ptr| {
            var spins: usize = 0;
            while (shard_ptr.done_pass.load(.acquire) != pass) {
                spins += 1;
                if (spins < 64) {
                    std.atomic.spinLoopHint();
                } else {
                    std.Thread.yield() catch {};
                }
            }
        }
    }

    pub fn broadcastStop(self: *ConnectionRegistry, io: std.Io) void {
        for (self.shards) |*shard_ptr| {
            shard_ptr.mutex.lockUncancelable(io);
            shard_ptr.condition.broadcast(io);
            shard_ptr.mutex.unlock(io);
        }
    }
};
