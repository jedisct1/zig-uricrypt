const std = @import("std");
const uricrypt = @import("root.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // Example usage
    const uri = "https://example.com/path/to/resource";
    const secret_key = "my_secret_key";
    const context = "test_context";

    // Encrypt
    const encrypted = try uricrypt.encryptUri(allocator, uri, secret_key, context);
    defer allocator.free(encrypted);

    std.debug.print("Original: {s}\n", .{uri});
    std.debug.print("Encrypted: {s}\n", .{encrypted});

    // Decrypt
    const decrypted = try uricrypt.decryptUri(allocator, encrypted, secret_key, context);
    defer allocator.free(decrypted);

    std.debug.print("Decrypted: {s}\n", .{decrypted});

    // Verify they match
    if (std.mem.eql(u8, uri, decrypted)) {
        std.debug.print("✓ Success: Round-trip encryption/decryption works!\n", .{});
    } else {
        std.debug.print("✗ Error: Decrypted value doesn't match original\n", .{});
    }
}
