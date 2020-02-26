const std = @import("std");
const Op = @import("op.zig");
const Module = @import("module.zig");
const util = @import("util.zig");

pub const Execution = @This();

instance: *Module.Instance,
stack: []align(8) Op.Fixval,
stack_top: usize,

current_frame: Frame,

pub fn getLocal(self: Execution, idx: usize) Op.Fixval {
    @panic("TODO");
}

pub fn setLocal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub fn getGlobal(self: Execution, idx: usize) Op.Fixval {
    @panic("TODO");
}

pub fn setGlobal(self: Execution, idx: usize, value: var) void {
    @panic("TODO");
}

pub fn memGet(self: Execution, start: usize, offset: usize, comptime length: usize) !*[length]u8 {
    const tail = start +% offset +% (length - 1);
    const is_overflow = tail < start;
    const is_seg_fault = tail >= self.instance.memory.len;
    if (is_overflow or is_seg_fault) {
        return error.OutOfBounds;
    }
    return @ptrCast(*[length]u8, &self.instance.memory[start + offset]);
}

const Frame = packed struct {
    func: u32,
    instr: u32,
    top: usize,
    _pad: std.meta.IntType(false, 128 - @bitSizeOf(usize) - 64) = 0,

    fn terminus() Frame {
        return @bitCast(u128, @as(u128, 0));
    }

    fn isTerminus(self: Frame) bool {
        return @bitCast(u128, self) == 0;
    }
};

pub fn run(instance: *Module.Instance, stack: []align(8) Op.Fixval, func_id: usize, params: []Op.Fixval) !Op.Fixval {
    var self = Execution{
        .instance = instance,
        .stack = stack,
        .stack_top = stack.len,
        .current_frame = Frame.terminus(),
    };

    // initCall assumes the params are already pushed onto the stack
    for (params) |param| {
        try self.push(Op.Fixval, param);
    }

    try self.initCall(func_id);

    while (true) {
        const func = self.instance.module.funcs[self.current_frame.func];
        if (self.current_frame.instr > func.instrs.len) {
            const result = self.unwindCall();

            if (self.current_frame.isTerminus()) {
                std.debug.assert(self.stack_top == self.stack.len);
                return result;
            } else {
                try self.push(Op.Fixval, result);
            }
        } else {
            const instr = func.instrs[self.current_frame.instr];

            //const pop_array: [*]align(8) Op.Fixval = self.stack.ptr + self.stack_top;
            const pop_array = @intToPtr([*]align(8) Op.Fixval, 8);
            self.stack_top += instr.op.pop.len;

            const result = try instr.op.step(&self, instr.arg, pop_array);
            if (result) |res| {
                try self.push(@TypeOf(res), res);
            }
            self.current_frame.instr += 1;
        }
    }
}

pub fn initCall(self: *Execution, func_id: usize) !void {
    const func = self.instance.module.funcs[func_id];
    // TODO: validate params on the callstack
    for (func.locals) |local| {
        try self.push(u128, 0);
    }

    try self.push(Frame, self.current_frame);
    self.current_frame = .{
        .func = @intCast(u32, func_id),
        .instr = 0,
        .top = @intCast(usize, self.stack_top),
    };
}

pub fn unwindCall(self: *Execution) Op.Fixval {
    const func = self.instance.module.funcs[self.current_frame.func];
    const func_type = self.instance.module.func_types[func.func_type];

    const result = self.pop(Op.Fixval);

    self.stack_top = self.current_frame.top;

    const prev_frame = self.pop(Frame);
    self.dropN(func.locals.len + func_type.params.len);

    self.push(Op.Fixval, result) catch unreachable;

    return result;
}

pub fn unwindBlock(self: *Execution, target_idx: u32) void {
    const func = self.instance.module.funcs[self.current_frame.func];

    var remaining = target_idx;
    var stack_change: isize = 0;
    // TODO: test this...
    while (true) {
        self.current_frame.instr += 1;
        const instr = func.instrs[self.current_frame.instr];

        stack_change -= @intCast(isize, instr.op.pop.len);
        stack_change += @intCast(isize, @boolToInt(instr.op.push != null));

        const swh = util.Swhash(8);
        switch (swh.match(instr.op.name)) {
            swh.case("block"), swh.case("loop"), swh.case("if") => {
                remaining += 1;
            },
            swh.case("end") => {
                if (remaining > 0) {
                    remaining -= 1;
                } else {
                    // TODO: actually find the corresponding opening block
                    const begin = instr;
                    const block_type = @intToEnum(Op.Arg.Type, begin.arg.U64);
                    const top_value = self.stack[self.stack_top];

                    std.debug.assert(stack_change <= 0);
                    self.dropN(std.math.absCast(stack_change));

                    if (std.mem.eql(u8, "loop", begin.op.name)) {
                        // self.current_frame.instr = begin_idx + 1;
                    } else if (block_type != .Void) {
                        self.push(Op.Fixval, top_value) catch unreachable;
                    }
                    return;
                }
            },
            else => {},
        }
    }
}

fn dropN(self: *Execution, size: usize) void {
    std.debug.assert(self.stack_top + size <= self.stack.len);
    self.stack_top += size;
}

fn pop(self: *Execution, comptime T: type) T {
    defer self.stack_top += @sizeOf(T);
    return @bitCast(T, self.stack[self.stack_top]);
}

fn push(self: *Execution, comptime T: type, value: T) !void {
    self.stack_top = try std.math.sub(usize, self.stack_top, 1);
    self.stack[self.stack_top] = @bitCast(Op.Fixval, value);
}
