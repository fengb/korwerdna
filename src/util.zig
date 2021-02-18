const std = @import("std");
/// Super simple "perfect hash" algorithm
/// Only really useful for switching on strings
// TODO: can we auto detect and promote the underlying type?
pub fn Swhash(comptime max_bytes: comptime_int) type {
    const T = std.meta.Int(.unsigned, max_bytes * 8);

    return struct {
        pub fn match(string: []const u8) T {
            return hash(string) orelse std.math.maxInt(T);
        }

        pub fn case(comptime string: []const u8) T {
            return hash(string) orelse @compileError("Cannot hash '" ++ string ++ "'");
        }

        fn hash(string: []const u8) ?T {
            if (string.len > max_bytes) return null;
            var tmp = [_]u8{0} ** max_bytes;
            std.mem.copy(u8, &tmp, string);
            return std.mem.readIntNative(T, &tmp);
        }
    };
}

pub const RingAllocator = struct {
    buffer: []u8,
    end_index: usize = 0,
    prev_size: usize = 0,
    allocator: std.mem.Allocator = .{
        .allocFn = alloc,
        .resizeFn = resize,
    },

    pub fn init(buffer: []u8) RingAllocator {
        return .{ .buffer = buffer };
    }

    /// NOTE: this will not work in all cases, if the last allocation had an adjusted_index
    ///       then we won't be able to determine what the last allocation was.  This is because
    ///       the alignForward operation done in alloc is not reverisible.
    pub fn isLastAllocation(self: *const RingAllocator, buf: []u8) bool {
        return buf.ptr + buf.len == self.buffer.ptr + self.end_index;
    }

    pub fn ownsSlice(self: *const RingAllocator, slice: []u8) bool {
        return @ptrToInt(slice.ptr) >= @ptrToInt(self.buffer.ptr) and
            (@ptrToInt(slice.ptr) + slice.len) <= (@ptrToInt(self.buffer.ptr) + self.buffer.len);
    }

    fn alloc(allocator: *std.mem.Allocator, n: usize, ptr_align: u29, len_align: u29, return_address: usize) error{OutOfMemory}![]u8 {
        const self = @fieldParentPtr(RingAllocator, "allocator", allocator);
        var aligned_addr = std.mem.alignForward(@ptrToInt(self.buffer.ptr) + self.end_index, ptr_align);
        var adjusted_index = aligned_addr - @ptrToInt(self.buffer.ptr);
        var new_end_index = adjusted_index + n;

        if (new_end_index > self.buffer.len) {
            // Wrap around the ring
            aligned_addr = std.mem.alignForward(@ptrToInt(self.buffer.ptr) + self.end_index, ptr_align);
            adjusted_index = aligned_addr - @ptrToInt(self.buffer.ptr);
            new_end_index = adjusted_index + n;

            // Prevent trampling over the previous allocation
            if (new_end_index > self.end_index - self.prev_size) {
                return error.OutOfMemory;
            }
        }

        const result = self.buffer[adjusted_index..new_end_index];
        self.prev_size = n;
        self.end_index = new_end_index;
        return result;
    }

    fn resize(allocator: *std.mem.Allocator, buf: []u8, buf_align: u29, new_size: usize, len_align: u29, return_address: usize) error{OutOfMemory}!usize {
        const self = @fieldParentPtr(RingAllocator, "allocator", allocator);
        std.debug.assert(self.ownsSlice(buf)); // sanity check

        if (!self.isLastAllocation(buf)) {
            if (new_size > buf.len)
                return error.OutOfMemory;
            return if (new_size == 0) 0 else std.mem.alignAllocLen(buf.len, new_size, len_align);
        }

        if (new_size <= buf.len) {
            const sub = buf.len - new_size;
            self.end_index -= sub;
            self.prev_size -= sub;
            return if (new_size == 0) 0 else std.mem.alignAllocLen(buf.len - sub, new_size, len_align);
        }

        const add = new_size - buf.len;
        if (add + self.end_index > self.buffer.len) {
            return error.OutOfMemory;
        }
        self.prev_size += add;
        self.end_index += add;
        return new_size;
    }
};
