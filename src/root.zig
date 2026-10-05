pub const Server = @import("./server/Server.zig").Server;
pub const ServerOptions = @import("./server/Server.zig").ServerOptions;
pub const MAX_MTU_SIZE = @import("./server/Server.zig").MAX_MTU_SIZE;
pub const Connection = @import("./server/Connection.zig").Connection;
pub const SharedPayload = @import("./proto/Frame.zig").SharedPayload;
pub const OutputSlab = @import("./server/OutputSlab.zig").OutputSlab;

pub const Socket = @import("./socket/socket.zig").Socket;
pub const Poller = @import("./socket/socket.zig").Poller;
pub const SocketCallbackFn = @import("./socket/socket.zig").CallbackFn;
pub const SocketError = @import("./socket/socket.zig").SocketError;

pub const Logger = @import("./misc/Logger.zig").Logger;
pub const LoggerColors = @import("./misc/Logger.zig").Colors;

pub const Proto = @import("./proto/root.zig");

pub const Client = @import("./client/client.zig").Client;
pub const ClientOptions = @import("./client/client.zig").ClientOptions;

pub const Priority = @import("./client/client.zig").Priority;
pub const ServerPriority = @import("./server/Connection.zig").Priority;
pub const Reliability = @import("./proto/Frame.zig").Reliability;

test "all" {
    std.testing.refAllDecls(@import("proto/offline/UnconnectedPong.zig"));
    std.testing.refAllDecls(@import("proto/offline/UnconnectedPing.zig"));
    std.testing.refAllDecls(@import("proto/offline/ConnectionRequest1.zig"));
    std.testing.refAllDecls(@import("proto/offline/ConnectionRequest2.zig"));
    std.testing.refAllDecls(@import("proto/offline/ConnectionReply1.zig"));
    std.testing.refAllDecls(@import("proto/offline/ConnectionReply2.zig"));

    std.testing.refAllDecls(@import("proto/online/Ack.zig"));
    std.testing.refAllDecls(@import("proto/online/ConnectionRequest.zig"));
    std.testing.refAllDecls(@import("proto/online/ConnectionRequestAccepted.zig"));
    std.testing.refAllDecls(@import("proto/online/FrameSet.zig"));

    // zero-input smoke pass for the fuzz targets
    std.testing.refAllDecls(@import("proto/fuzz.zig"));
}

const std = @import("std");
