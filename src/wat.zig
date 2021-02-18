const std = @import("std");
const Module = @import("module.zig");
const Op = @import("op.zig");
const util = @import("util.zig");

const debug_buffer = std.builtin.mode == .Debug;

fn sexpr(reader: anytype) Sexpr(@TypeOf(reader)) {
    return .{
        .reader = reader,
        ._debug_buffer = if (debug_buffer)
            std.fifo.LinearFifo(u8, .{ .Static = 0x100 }).init()
        else {},
    };
}

fn Sexpr(comptime Reader: type) type {
    return struct {
        const Self = @This();

        reader: Reader,
        current_stack: isize = 0,
        _peek: ?u8 = null,
        _debug_buffer: if (debug_buffer)
            std.fifo.LinearFifo(u8, .{ .Static = 0x100 })
        else
            void,

        const Token = enum {
            OpenParen,
            CloseParen,
            Atom,
        };

        pub const List = struct {
            ctx: *Self,
            stack_level: isize,

            const Next = union(enum) { Atom: []const u8, List: List };

            pub fn next(self: List, allocator: *std.mem.Allocator) !?Next {
                if (self.isAtEnd()) return null;

                return switch (try self.ctx.scan()) {
                    .OpenParen => Next{ .List = .{ .ctx = self.ctx, .stack_level = self.ctx.current_stack } },
                    .CloseParen => null,
                    .Atom => Next{ .Atom = try self.loadIntoAllocator(allocator) },
                };
            }

            pub fn obtainAtom(self: List, allocator: *std.mem.Allocator) ![]u8 {
                return (try self.nextAtom(allocator)) orelse error.ExpectedAtomGotNull;
            }

            pub fn obtainList(self: List) !List {
                return (try self.nextList()) orelse error.ExpectedListGotNull;
            }

            pub fn nextAtom(self: List, allocator: *std.mem.Allocator) !?[]u8 {
                if (self.isAtEnd()) return null;

                return switch (try self.ctx.scan()) {
                    .OpenParen => error.ExpectedAtomGotList,
                    .CloseParen => null,
                    .Atom => try self.loadIntoAllocator(allocator),
                };
            }

            pub fn nextList(self: List) !?List {
                if (self.isAtEnd()) return null;

                return switch (try self.ctx.scan()) {
                    .OpenParen => List{ .ctx = self.ctx, .stack_level = self.ctx.current_stack },
                    .CloseParen => null,
                    .Atom => error.ExpectedListGotAtom,
                };
            }

            pub fn expectEnd(self: List) !void {
                if (self.isAtEnd()) return;

                switch (try self.ctx.scan()) {
                    .CloseParen => {},
                    else => return error.ExpectedEndOfList,
                }
            }

            fn isAtEnd(self: List) bool {
                switch (self.stack_level - self.ctx.current_stack) {
                    0 => return false,
                    1 => {
                        if (debug_buffer and self.ctx._debug_buffer.peekItem(self.ctx._debug_buffer.count - 1) != ')') {
                            self.ctx.debugDump(std.io.getStdOut().writer()) catch {};
                            unreachable;
                        }
                        return true;
                    },
                    else => {
                        if (debug_buffer) {
                            self.ctx.debugDump(std.io.getStdOut().writer()) catch {};
                            std.debug.print("Unexpected list depth -- Current {} != List {}\n", .{ self.ctx.current_stack, self.stack_level });
                        }
                        unreachable;
                    },
                }
            }

            fn loadIntoAllocator(self: List, allocator: *std.mem.Allocator) ![]u8 {
                var list = std.ArrayList(u8).init(allocator);
                const writer = list.writer();

                const first = try self.ctx.readByte();
                try writer.writeByte(first);
                const is_string = first == '"';

                while (true) {
                    const byte = try self.ctx.readByte();
                    if (is_string) {
                        try writer.writeByte(byte);

                        // TODO: handle escape sequences?
                        if (byte == '"') {
                            return list.toOwnedSlice();
                        }
                    } else {
                        switch (byte) {
                            0, ' ', '\t', '\n', '(', ')' => {
                                self.ctx.putBack(byte);
                                return list.toOwnedSlice();
                            },
                            else => try writer.writeByte(byte),
                        }
                    }
                }
            }
        };

        pub fn root(self: *Self) !List {
            const token = try self.scan();
            std.debug.assert(token == .OpenParen);
            return List{ .ctx = self, .stack_level = self.current_stack };
        }

        pub fn debugDump(self: Self, writer: anytype) !void {
            var tmp = self._debug_buffer;
            const reader = tmp.reader();

            var buf: [0x100]u8 = undefined;
            const size = try reader.read(&buf);
            try writer.writeAll(buf[0..size]);
            try writer.writeByte('\n');
        }

        fn skipPast(self: *Self, seq: []const u8) !void {
            std.debug.assert(seq.len > 0);

            var matched: usize = 0;
            while (true) {
                const byte = try self.readByte();
                if (byte == seq[matched]) {
                    matched += 1;
                    if (matched >= seq.len) {
                        return;
                    }
                } else {
                    matched = 0;
                }
            }
        }

        pub fn expectEos(self: *Self) !void {
            const value = self.scan() catch |err| switch (err) {
                error.EndOfStream => return,
                else => return err,
            };

            return error.ExpectEos;
        }

        fn readByte(self: *Self) !u8 {
            if (self._peek) |p| {
                self._peek = null;
                return p;
            } else {
                const byte = try self.reader.readByte();
                if (debug_buffer) {
                    if (self._debug_buffer.writableLength() == 0) {
                        self._debug_buffer.discard(1);
                        std.debug.assert(self._debug_buffer.writableLength() == 1);
                    }
                    self._debug_buffer.writeAssumeCapacity(&[_]u8{byte});
                }
                return byte;
            }
        }

        fn peek(self: *Self) !u8 {
            return self._peek orelse {
                const byte = try self.readByte();
                self._peek = byte;
                return byte;
            };
        }

        fn putBack(self: *Self, byte: u8) void {
            std.debug.assert(self._peek == null);
            self._peek = byte;
        }

        fn scan(self: *Self) !Token {
            while (true) {
                const byte = try self.readByte();
                switch (byte) {
                    0, ' ', '\t', '\n' => {},
                    '(' => {
                        const next = self.peek() catch |err| switch (err) {
                            error.EndOfStream => 0,
                            else => return err,
                        };

                        if (next == ';') {
                            // Comment block -- skip to next segment
                            try self.skipPast(";)");
                        } else {
                            self.current_stack += 1;
                            return Token.OpenParen;
                        }
                    },
                    ')' => {
                        if (self.current_stack <= 0) {
                            return error.UnmatchedParens;
                        }
                        self.current_stack -= 1;
                        return Token.CloseParen;
                    },
                    ';' => try self.skipPast("\n"),
                    else => {
                        self.putBack(byte);
                        if (self.current_stack <= 0) {
                            return error.TrailingLiteral;
                        }
                        return Token.Atom;
                    },
                }
            }
        }
    };
}

test "sexpr" {
    var buf: [0x100]u8 = undefined;
    var ring = util.RingAllocator.init(&buf);
    {
        var fbs = std.io.fixedBufferStream("(a bc 42)");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        std.testing.expectEqualSlices(u8, "a", try root.obtainAtom(&ring.allocator));
        std.testing.expectEqualSlices(u8, "bc", try root.obtainAtom(&ring.allocator));
        std.testing.expectEqualSlices(u8, "42", try root.obtainAtom(&ring.allocator));
        try root.expectEnd();
        try root.expectEnd();
        try root.expectEnd();
    }
    {
        var fbs = std.io.fixedBufferStream("(() ())");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        const first = try root.obtainList();
        std.testing.expectEqual(@as(?@TypeOf(root), null), try first.nextList());

        const second = try root.obtainList();
        std.testing.expectEqual(@as(?@TypeOf(root), null), try second.nextList());
    }
    {
        var fbs = std.io.fixedBufferStream("( ( ( ())))");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        const first = try root.obtainList();
        const second = try first.obtainList();
        const third = try second.obtainList();
        try third.expectEnd();
        try second.expectEnd();
        try first.expectEnd();
    }
    {
        var fbs = std.io.fixedBufferStream("(block (; ; ; ;) ;; label = @1\n  local.get 4)");
        var s = sexpr(fbs.reader());

        const root = try s.root();

        std.testing.expectEqualSlices(u8, "block", try root.obtainAtom(&ring.allocator));
        std.testing.expectEqualSlices(u8, "local.get", try root.obtainAtom(&ring.allocator));
        std.testing.expectEqualSlices(u8, "4", try root.obtainAtom(&ring.allocator));
        try root.expectEnd();
    }
}

pub fn parse(allocator: *std.mem.Allocator, reader: anytype) !Module {
    var result = try parseNoValidate(allocator, reader);
    errdefer result.deinit();

    try result.post_process();
    return result;
}

pub fn parseNoValidate(allocator: *std.mem.Allocator, reader: anytype) !Module {
    var ctx = sexpr(reader);
    const root = try ctx.root();

    errdefer if (debug_buffer) ctx.debugDump(std.io.getStdOut().writer()) catch {};

    var ring_buf: [0x1000]u8 = undefined;
    var ring = util.RingAllocator.init(&ring_buf);

    if (!std.mem.eql(u8, try root.obtainAtom(&ring.allocator), "module")) {
        return error.ExpectModule;
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();

    var customs = std.ArrayList(Module.Section(.custom)).init(&arena.allocator);
    var types = std.ArrayList(Module.Section(.type)).init(&arena.allocator);
    var imports = std.ArrayList(Module.Section(.import)).init(&arena.allocator);
    var functions = std.ArrayList(Module.Section(.function)).init(&arena.allocator);
    var tables = std.ArrayList(Module.Section(.table)).init(&arena.allocator);
    var memories = std.ArrayList(Module.Section(.memory)).init(&arena.allocator);
    var globals = std.ArrayList(Module.Section(.global)).init(&arena.allocator);
    var exports = std.ArrayList(Module.Section(.@"export")).init(&arena.allocator);
    var start: ?Module.Section(.start) = null;
    var elements = std.ArrayList(Module.Section(.element)).init(&arena.allocator);
    var codes = std.ArrayList(Module.Section(.code)).init(&arena.allocator);
    var data = std.ArrayList(Module.Section(.data)).init(&arena.allocator);

    while (try root.nextList()) |command| {
        const swhash = util.Swhash(8);

        switch (swhash.match(try command.obtainAtom(&ring.allocator))) {
            swhash.case("memory") => {
                try memories.append(.{
                    .limits = .{
                        .initial = try std.fmt.parseInt(u32, try command.obtainAtom(&ring.allocator), 10),
                        .maximum = if (try command.nextAtom(&ring.allocator)) |value|
                            try std.fmt.parseInt(u32, value, 10)
                        else
                            null,
                    },
                });
                // TODO: this is broken
                // try command.expectEnd();
            },
            swhash.case("type") => {
                while (try command.nextList()) |args| {
                    switch (swhash.match(try args.obtainAtom(&ring.allocator))) {
                        swhash.case("func") => {
                            var params = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                            var result: ?Module.Type.Value = null;

                            while (try args.nextList()) |pair| {
                                const loc = try pair.obtainAtom(&ring.allocator);

                                const typ: Module.Type.Value = switch (swhash.match(try pair.obtainAtom(&ring.allocator))) {
                                    swhash.case("i32") => .I32,
                                    swhash.case("i64") => .I64,
                                    swhash.case("f32") => .F32,
                                    swhash.case("f64") => .F64,
                                    else => return error.ExpectedType,
                                };

                                switch (swhash.match(loc)) {
                                    swhash.case("param") => try params.append(typ),
                                    swhash.case("result") => result = typ,
                                    else => return error.ExpectedLoc,
                                }

                                try pair.expectEnd();
                            }

                            try types.append(.{
                                .form = .Func,
                                .param_types = params.items,
                                .return_type = result,
                            });
                        },
                        else => return error.TypeNotRecognized,
                    }
                }
            },
            swhash.case("import") => {
                const module = try command.obtainAtom(&ring.allocator);
                if (module[0] != '"') {
                    return error.ExpectString;
                }

                const field = try command.obtainAtom(&ring.allocator);
                if (field[0] != '"') {
                    return error.ExpectString;
                }

                var result = Module.Section(.import){
                    .module = try arena.allocator.dupe(u8, module[1 .. module.len - 1]),
                    .field = try arena.allocator.dupe(u8, field[1 .. field.len - 1]),
                    .kind = undefined,
                };

                const kind_list = try command.obtainList();
                switch (swhash.match(try kind_list.obtainAtom(&ring.allocator))) {
                    swhash.case("func") => {
                        const type_pair = try kind_list.obtainList();

                        if (!std.mem.eql(u8, "type", try type_pair.obtainAtom(&ring.allocator))) {
                            @panic("TODO inline function prototypes");
                        }

                        const index = try type_pair.obtainAtom(&ring.allocator);
                        try type_pair.expectEnd();
                        result.kind = .{
                            .Function = @intToEnum(Module.Index.FuncType, try std.fmt.parseInt(u32, index, 10)),
                        };
                    },
                    swhash.case("table") => @panic("TODO"),
                    swhash.case("memory") => @panic("TODO"),
                    swhash.case("global") => @panic("TODO"),
                    else => return error.ImportNotSupported,
                }

                try kind_list.expectEnd();
                try command.expectEnd();

                try imports.append(result);
            },
            swhash.case("func") => {
                var params = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var locals = std.ArrayList(Module.Type.Value).init(&arena.allocator);
                var result: ?Module.Type.Value = null;

                while (command.obtainList()) |pair| {
                    const loc = try pair.obtainAtom(&ring.allocator);

                    const typ: Module.Type.Value = switch (swhash.match(try pair.obtainAtom(&ring.allocator))) {
                        swhash.case("i32") => .I32,
                        swhash.case("i64") => .I64,
                        swhash.case("f32") => .F32,
                        swhash.case("f64") => .F64,
                        else => return error.ExpectedType,
                    };

                    switch (swhash.match(loc)) {
                        swhash.case("param") => try params.append(typ),
                        swhash.case("local") => try locals.append(typ),
                        swhash.case("result") => result = typ,
                        else => return error.ExpectedLoc,
                    }

                    try pair.expectEnd();
                } else |err| switch (err) {
                    error.ExpectedListGotNull, error.ExpectedListGotAtom => {},
                    else => return err,
                }

                var body = std.ArrayList(Module.Instr).init(&arena.allocator);
                while (try command.nextAtom(&ring.allocator)) |op_string| {
                    for (op_string) |*letter| {
                        if (letter.* == '.') {
                            letter.* = '_';
                        }
                    }
                    const op = std.meta.stringToEnum(std.wasm.Opcode, op_string) orelse return error.OpNotFound;
                    const op_meta = Op.Meta.of(op);

                    try body.append(.{
                        .op = op,
                        .pop_len = @intCast(u8, op_meta.pop.len),
                        .arg = switch (op_meta.arg_kind) {
                            .Void => undefined,
                            .Type => blk: {
                                const pair = command.obtainList() catch |err| switch (err) {
                                    error.ExpectedListGotAtom => break :blk Op.Arg{ .Type = .Void },
                                    else => |e| return e,
                                };
                                if (!std.mem.eql(u8, try pair.obtainAtom(&ring.allocator), "result")) {
                                    return error.ExpectedResult;
                                }

                                const typ: Op.Arg.Type = switch (swhash.match(try pair.obtainAtom(&ring.allocator))) {
                                    swhash.case("void") => .Void,
                                    swhash.case("i32") => .I32,
                                    swhash.case("i64") => .I64,
                                    swhash.case("f32") => .F32,
                                    swhash.case("f64") => .F64,
                                    else => return error.ExpectedType,
                                };

                                try pair.expectEnd();
                                break :blk Op.Arg{ .Type = typ };
                            },
                            .U32z, .Mem, .Array => @panic("TODO"),
                            else => blk: {
                                const arg = try command.obtainAtom(&ring.allocator);
                                break :blk @as(Op.Arg, switch (op_meta.arg_kind) {
                                    .Void, .Type, .U32z, .Mem, .Array => unreachable,
                                    .I32 => .{ .I32 = try std.fmt.parseInt(i32, arg, 10) },
                                    .U32 => .{ .U32 = try std.fmt.parseInt(u32, arg, 10) },
                                    .I64 => .{ .I64 = try std.fmt.parseInt(i64, arg, 10) },
                                    .U64 => .{ .U64 = try std.fmt.parseInt(u64, arg, 10) },
                                    .F32 => .{ .F32 = try std.fmt.parseFloat(f32, arg) },
                                    .F64 => .{ .F64 = try std.fmt.parseFloat(f64, arg) },
                                });
                            },
                        },
                    });
                }

                try functions.append(.{
                    .type_idx = @intToEnum(Module.Index.FuncType, @intCast(u32, types.items.len)),
                });

                try codes.append(.{
                    .locals = locals.items,
                    .body = body.items,
                });

                try types.append(.{
                    .form = .Func,
                    .param_types = params.items,
                    .return_type = result,
                });
            },
            swhash.case("global") => {
                // 'skip' the id
                const id = (try command.next(&ring.allocator)) orelse return error.ExpectedNext;

                const next = blk: {
                    // a comment was skipped so 'id' is the actual Atom/List we want
                    if (id != .Atom or id.Atom[0] != '$') break :blk id;

                    // if it was an id get next list/atom
                    break :blk (try command.next(&ring.allocator)) orelse return error.ExpectedNext;
                };

                const mutable = blk: {
                    if (next == .Atom) break :blk false;

                    const mut = try next.List.obtainAtom(&ring.allocator);
                    break :blk std.mem.eql(u8, mut, "mut");
                };

                const valtype = blk: {
                    const type_atom = switch (next) {
                        .List => |list| list_blk: {
                            const res = try list.obtainAtom(&ring.allocator);
                            try list.expectEnd();
                            break :list_blk res;
                        },
                        .Atom => |atom| atom,
                    };
                    break :blk @as(Module.Type.Value, switch (swhash.match(type_atom)) {
                        swhash.case("i32") => .I32,
                        swhash.case("i64") => .I64,
                        swhash.case("f32") => .F32,
                        swhash.case("f64") => .F64,
                        else => return error.ExpectedType,
                    });
                };

                const init_pair = try command.obtainList();
                var op_string = try init_pair.obtainAtom(&ring.allocator);
                for (op_string) |*letter| {
                    if (letter.* == '.') {
                        letter.* = '_';
                    }
                }

                const op = std.meta.stringToEnum(std.wasm.Opcode, op_string) orelse return error.OpNotFound;

                const value = try init_pair.obtainAtom(&ring.allocator);

                const result: Module.InitExpr = switch (op) {
                    .i32_const => .{ .i32_const = try std.fmt.parseInt(i32, value, 10) },
                    .i64_const => .{ .i64_const = try std.fmt.parseInt(i64, value, 10) },
                    .f32_const => .{ .f32_const = try std.fmt.parseFloat(f32, value) },
                    .f64_const => .{ .f64_const = try std.fmt.parseFloat(f64, value) },
                    else => return error.UnsupportedInitExpr,
                };

                try init_pair.expectEnd();

                try globals.append(.{
                    .@"type" = .{
                        .content_type = valtype,
                        .mutability = mutable,
                    },
                    .init = result,
                });
            },
            swhash.case("export") => {
                const export_name = try command.obtainAtom(&ring.allocator);
                if (export_name[0] != '"') {
                    return error.ExpectString;
                }
                std.debug.assert(export_name[export_name.len - 1] == '"');

                const pair = try command.obtainList();

                const kind = try pair.obtainAtom(&ring.allocator);
                const index = try pair.obtainAtom(&ring.allocator);

                try exports.append(.{
                    .field = try arena.allocator.dupe(u8, export_name[1 .. export_name.len - 1]),
                    .kind = switch (swhash.match(kind)) {
                        swhash.case("func") => .Function,
                        swhash.case("table") => .Table,
                        swhash.case("memory") => .Memory,
                        swhash.case("global") => .Global,
                        else => return error.ExpectExternalKind,
                    },
                    .index = try std.fmt.parseInt(u32, index, 10),
                });

                try pair.expectEnd();
            },
            else => return error.CommandNotRecognized,
        }
        try command.expectEnd();
    }

    try root.expectEnd();
    try ctx.expectEos();

    return Module{
        .custom = customs.items,
        .@"type" = types.items,
        .import = imports.items,
        .function = functions.items,
        .table = tables.items,
        .memory = memories.items,
        .global = globals.items,
        .@"export" = exports.items,
        .start = start,
        .element = elements.items,
        .code = codes.items,
        .data = data.items,

        .arena = arena,
    };
}

test "parseNoValidate" {
    {
        var fbs = std.io.fixedBufferStream("(module)");
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 0), module.memory.len);
        std.testing.expectEqual(@as(usize, 0), module.function.len);
        std.testing.expectEqual(@as(usize, 0), module.@"export".len);
    }
    {
        var fbs = std.io.fixedBufferStream("(module (memory 42))");
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.memory.len);
        std.testing.expectEqual(@as(u32, 42), module.memory[0].limits.initial);
    }
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (func (param i64) (param f32) (result i64) (local f64)
            \\    local.get 0
            \\    drop
            \\    local.get 0))
        );
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.function.len);

        const func_type = module.@"type"[0];
        std.testing.expectEqual(@as(usize, 2), func_type.param_types.len);
        std.testing.expectEqual(Module.Type.Value.I64, func_type.param_types[0]);
        std.testing.expectEqual(Module.Type.Value.F32, func_type.param_types[1]);
        std.testing.expectEqual(Module.Type.Value.I64, func_type.return_type.?);

        const code = module.code[0];

        std.testing.expectEqual(@as(usize, 1), code.locals.len);
        std.testing.expectEqual(Module.Type.Value.F64, code.locals[0]);

        std.testing.expectEqual(@as(usize, 3), code.body.len);
    }
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (func (param i32) (result i32) local.get 0)
            \\  (export "foo" (func 0)))
        );
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.function.len);

        std.testing.expectEqual(@as(usize, 1), module.@"export".len);
        std.testing.expectEqualSlices(u8, "foo", module.@"export"[0].field);
        std.testing.expectEqual(Module.ExternalKind.Function, module.@"export"[0].kind);
        std.testing.expectEqual(@as(u32, 0), module.@"export"[0].index);
    }
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (type (;0;) (func (param i32) (result i32)))
            \\  (import "env" "fibonacci" (func (type 0))))
        );
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 1), module.@"type".len);
        std.testing.expectEqual(Module.Type.Form.Func, module.@"type"[0].form);
        std.testing.expectEqual(@as(usize, 1), module.@"type"[0].param_types.len);
        std.testing.expectEqual(Module.Type.Value.I32, module.@"type"[0].param_types[0]);
        std.testing.expectEqual(Module.Type.Value.I32, module.@"type"[0].return_type.?);

        std.testing.expectEqual(@as(usize, 1), module.import.len);
        std.testing.expectEqualSlices(u8, "env", module.import[0].module);
        std.testing.expectEqualSlices(u8, "fibonacci", module.import[0].field);
        std.testing.expectEqual(Module.ExternalKind.Function, module.import[0].kind);
        std.testing.expectEqual(@intToEnum(Module.Index.FuncType, 0), module.import[0].kind.Function);

        std.testing.expectEqual(@as(usize, 0), module.function.len);
    }
    {
        var fbs = std.io.fixedBufferStream(
            \\(module
            \\  (global $x (mut i32) (i32.const -12))
            \\  (global $x i64 (i64.const 12))
            \\  (global (;1;) i32 (i32.const 10)))
        );
        var module = try parseNoValidate(std.testing.allocator, fbs.reader());
        defer module.deinit();

        std.testing.expectEqual(@as(usize, 3), module.global.len);
        std.testing.expectEqual(Module.Type.Value.I32, module.global[0].@"type".content_type);
        std.testing.expectEqual(true, module.global[0].@"type".mutability);
        std.testing.expectEqual(@as(i32, -12), module.global[0].init.i32_const);

        std.testing.expectEqual(Module.Type.Value.I64, module.global[1].@"type".content_type);
        std.testing.expectEqual(false, module.global[1].@"type".mutability);
        std.testing.expectEqual(@as(i64, 12), module.global[1].init.i64_const);

        std.testing.expectEqual(Module.Type.Value.I32, module.global[2].@"type".content_type);
        std.testing.expectEqual(false, module.global[2].@"type".mutability);
        std.testing.expectEqual(@as(i32, 10), module.global[2].init.i32_const);
    }
}

test "parse blocks" {
    var fbs = std.io.fixedBufferStream(
        \\(module
        \\  (func (result i32)
        \\    block (result i32)
        \\      loop
        \\      br 0
        \\      br 1
        \\      end
        \\    end))
    );
    var module = try parseNoValidate(std.testing.allocator, fbs.reader());
    defer module.deinit();

    const body = module.code[0].body;
    std.testing.expectEqual(@as(usize, 6), body.len);

    std.testing.expectEqual(std.wasm.Opcode.block, body[0].op);
    std.testing.expectEqual(Op.Arg.Type.I32, body[0].arg.Type);

    std.testing.expectEqual(std.wasm.Opcode.loop, body[1].op);
    std.testing.expectEqual(Op.Arg.Type.Void, body[1].arg.Type);

    std.testing.expectEqual(std.wasm.Opcode.br, body[2].op);
    std.testing.expectEqual(@as(u32, 0), body[2].arg.U32);

    std.testing.expectEqual(std.wasm.Opcode.br, body[3].op);
    std.testing.expectEqual(@as(u32, 1), body[3].arg.U32);

    std.testing.expectEqual(std.wasm.Opcode.end, body[4].op);

    std.testing.expectEqual(std.wasm.Opcode.end, body[5].op);
}
