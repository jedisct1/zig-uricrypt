const std = @import("std");
const crypto = std.crypto;
const sha3 = crypto.hash.sha3;
const base64 = std.base64;

const siv_size: usize = 16;

const UriComponents = struct {
    scheme: ?[]const u8,
    rest: []const u8,

    fn iterator(self: UriComponents) UriComponentIterator {
        // Handle empty rest
        if (self.rest.len == 0) {
            return UriComponentIterator{
                .rest = "",
                .position = 0,
                .done = true,
            };
        }

        // Simply iterate over the rest regardless of scheme or path type
        return UriComponentIterator{
            .rest = self.rest,
            .position = 0,
            .done = false,
        };
    }
};

const UriComponentIterator = struct {
    rest: []const u8,
    position: usize,
    done: bool,

    fn next(self: *UriComponentIterator) ?[]const u8 {
        if (self.done) {
            return null;
        }

        if (self.position >= self.rest.len) {
            self.done = true;
            return null;
        }

        // Find next component ending with '/', '?', or '#'
        const remaining = self.rest[self.position..];
        var end_pos: ?usize = null;

        // Find the nearest terminator ('/', '?', or '#')
        for (remaining, 0..) |ch, i| {
            if (ch == '/' or ch == '?' or ch == '#') {
                end_pos = i;
                break;
            }
        }

        if (end_pos) |pos| {
            const end = self.position + pos + 1; // Include the terminator
            const component = self.rest[self.position..end];
            self.position = end;
            return component;
        }

        // Last component (no trailing terminator)
        if (self.position < self.rest.len) {
            const component = self.rest[self.position..];
            self.done = true;
            return component;
        }

        self.done = true;
        return null;
    }
};

fn splitUri(uri: []const u8) UriComponents {
    // Check if this is a URI with a scheme
    if (std.mem.indexOf(u8, uri, "://")) |scheme_end| {
        const scheme = uri[0 .. scheme_end + 3]; // Include "://"
        const rest = uri[scheme_end + 3 ..];
        return UriComponents{
            .scheme = scheme,
            .rest = rest,
        };
    }

    // No scheme found - treat as path-only URI
    return UriComponents{
        .scheme = null,
        .rest = uri,
    };
}

fn xorInPlace(data: []u8, keystream: []const u8) void {
    const len = @min(data.len, keystream.len);
    for (0..len) |i| {
        data[i] ^= keystream[i];
    }
}

pub fn encryptUri(
    allocator: std.mem.Allocator,
    uri: []const u8,
    secret_key: []const u8,
    context: []const u8,
) ![]u8 {
    const components = splitUri(uri);

    var encrypted_uri = std.ArrayList(u8){};
    defer encrypted_uri.deinit(allocator);

    var base_hasher = sha3.TurboShake128(0x1F).init(.{});
    base_hasher.update(&[_]u8{@intCast(secret_key.len)});
    base_hasher.update(secret_key);
    base_hasher.update(&[_]u8{@intCast(context.len)});
    base_hasher.update(context);

    var components_hasher = base_hasher;
    components_hasher.update("IV");
    var base_keystream_hasher = base_hasher;
    base_keystream_hasher.update("KS");

    var uri_parts_iter = components.iterator();

    while (uri_parts_iter.next()) |part| {
        const part_bytes = part;

        const total_unpadded = siv_size + part_bytes.len;
        const padding = (3 - (total_unpadded % 3)) % 3;

        components_hasher.update(part_bytes);

        var siv: [siv_size]u8 = undefined;
        var siv_hasher = components_hasher;
        siv_hasher.squeeze(&siv);

        var keystream_hasher = base_keystream_hasher;
        keystream_hasher.update(&siv);

        const encrypted_part_len = part_bytes.len + padding;
        var encrypted_part = try allocator.alloc(u8, encrypted_part_len);
        defer allocator.free(encrypted_part);

        @memset(encrypted_part, 0);
        @memcpy(encrypted_part[0..part_bytes.len], part_bytes);

        const keystream = try allocator.alloc(u8, encrypted_part_len);
        defer allocator.free(keystream);
        keystream_hasher.squeeze(keystream);

        xorInPlace(encrypted_part, keystream);

        try encrypted_uri.appendSlice(allocator, &siv);
        try encrypted_uri.appendSlice(allocator, encrypted_part);
    }

    var result = std.ArrayList(u8){};
    errdefer result.deinit(allocator);

    if (components.scheme) |scheme| {
        try result.appendSlice(allocator, scheme);
    } else {
        // Prepend '/' to indicate this is a path-only URI
        try result.append(allocator, '/');
    }

    // Encode to base64
    const encoder = &base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(encrypted_uri.items.len);
    const start_pos = result.items.len;
    try result.resize(allocator, start_pos + encoded_len);
    _ = encoder.encode(result.items[start_pos..], encrypted_uri.items);

    return result.toOwnedSlice(allocator);
}

pub fn decryptUri(
    allocator: std.mem.Allocator,
    encrypted_uri: []const u8,
    secret_key: []const u8,
    context: []const u8,
) ![]u8 {
    var scheme: ?[]const u8 = null;
    var encrypted_part: []const u8 = undefined;

    if (std.mem.startsWith(u8, encrypted_uri, "/")) {
        encrypted_part = encrypted_uri[1..];
    } else if (std.mem.indexOf(u8, encrypted_uri, "://")) |scheme_end| {
        scheme = encrypted_uri[0 .. scheme_end + 3];
        encrypted_part = encrypted_uri[scheme_end + 3 ..];

        if (encrypted_part.len == 0) {
            return allocator.dupe(u8, scheme.?);
        }
    } else {
        return error.DecryptionFailed;
    }

    const decoder = &base64.url_safe_no_pad.Decoder;
    const max_decoded_len = decoder.calcSizeUpperBound(encrypted_part.len) catch {
        return error.DecryptionFailed;
    };
    var encrypted_bytes = try allocator.alloc(u8, max_decoded_len);
    defer allocator.free(encrypted_bytes);

    const decode_len = decoder.calcSizeForSlice(encrypted_part) catch {
        return error.DecryptionFailed;
    };
    decoder.decode(encrypted_bytes[0..decode_len], encrypted_part) catch {
        return error.DecryptionFailed;
    };
    encrypted_bytes = encrypted_bytes[0..decode_len];

    var result = std.ArrayList(u8){};
    errdefer result.deinit(allocator);

    // Add scheme if present
    if (scheme) |s| {
        try result.appendSlice(allocator, s);
    }

    var pos: usize = 0;

    var base_hasher = sha3.TurboShake128(0x1F).init(.{});
    base_hasher.update(&[_]u8{@intCast(secret_key.len)});
    base_hasher.update(secret_key);
    base_hasher.update(&[_]u8{@intCast(context.len)});
    base_hasher.update(context);

    var components_hasher = base_hasher;
    components_hasher.update("IV");

    var base_keystream_hasher = base_hasher;
    base_keystream_hasher.update("KS");

    while (pos < encrypted_bytes.len) {
        if (pos + siv_size > encrypted_bytes.len) {
            return error.DecryptionFailed;
        }

        const siv = encrypted_bytes[pos .. pos + siv_size];
        const component_start = pos + siv_size;
        pos += siv_size;

        var keystream_hasher = base_keystream_hasher;
        keystream_hasher.update(siv);

        // Track component start position in result
        const component_result_start = result.items.len;

        // Create a buffer for reading keystream bytes
        var keystream_buffer: [1024]u8 = undefined;
        var keystream_pos: usize = 0;
        var keystream_len: usize = 0;

        // Decrypt bytes directly into result
        while (pos < encrypted_bytes.len) {
            // Refill keystream buffer if needed
            if (keystream_pos >= keystream_len) {
                const to_read = @min(keystream_buffer.len, encrypted_bytes.len - pos);
                keystream_hasher.squeeze(keystream_buffer[0..to_read]);
                keystream_len = to_read;
                keystream_pos = 0;
            }

            const decrypted_byte = encrypted_bytes[pos] ^ keystream_buffer[keystream_pos];
            pos += 1;
            keystream_pos += 1;

            if (decrypted_byte == 0) {
                continue;
            }

            try result.append(allocator, decrypted_byte);

            // Check if this byte is a terminator ('/', '?', or '#')
            if (decrypted_byte == '/' or decrypted_byte == '?' or decrypted_byte == '#') {
                const bytes_read = pos - component_start;
                const total_len = siv_size + bytes_read;
                const padding_needed = (3 - (total_len % 3)) % 3;
                pos += padding_needed;
                keystream_pos += padding_needed;
                break;
            }
        }

        const component_slice = result.items[component_result_start..];
        if (component_slice.len == 0) {
            return error.DecryptionFailed;
        }

        components_hasher.update(component_slice);

        var expected_siv: [siv_size]u8 = undefined;
        var siv_hasher = components_hasher;
        siv_hasher.squeeze(&expected_siv);

        if (!std.mem.eql(u8, &expected_siv, siv)) {
            return error.DecryptionFailed;
        }
    }

    if (result.items.len == 0 or (scheme == null and result.items.len == 0)) {
        return error.DecryptionFailed;
    }

    return result.toOwnedSlice(allocator);
}

test "split_uri_basic" {
    const uri = "https://example.com";
    const result = splitUri(uri);

    try std.testing.expectEqualStrings("https://", result.scheme.?);

    var iter = result.iterator();
    const first = iter.next().?;
    try std.testing.expectEqualStrings("example.com", first);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_with_path" {
    const uri = "https://example.com/a/b/c";
    const result = splitUri(uri);

    try std.testing.expectEqualStrings("https://", result.scheme.?);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("example.com/", iter.next().?);
    try std.testing.expectEqualStrings("a/", iter.next().?);
    try std.testing.expectEqualStrings("b/", iter.next().?);
    try std.testing.expectEqualStrings("c", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_path_only_absolute" {
    const uri = "/path/to/file";
    const result = splitUri(uri);

    try std.testing.expect(result.scheme == null);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("/", iter.next().?);
    try std.testing.expectEqualStrings("path/", iter.next().?);
    try std.testing.expectEqualStrings("to/", iter.next().?);
    try std.testing.expectEqualStrings("file", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_path_only_relative" {
    const uri = "path/to/file";
    const result = splitUri(uri);

    try std.testing.expect(result.scheme == null);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("path/", iter.next().?);
    try std.testing.expectEqualStrings("to/", iter.next().?);
    try std.testing.expectEqualStrings("file", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_single_slash" {
    const uri = "/";
    const result = splitUri(uri);

    try std.testing.expect(result.scheme == null);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("/", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_with_query_params" {
    const uri = "https://example.com/path?foo=bar&baz=qux";
    const result = splitUri(uri);

    try std.testing.expectEqualStrings("https://", result.scheme.?);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("example.com/", iter.next().?);
    try std.testing.expectEqualStrings("path?", iter.next().?);
    try std.testing.expectEqualStrings("foo=bar&baz=qux", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_with_fragment" {
    const uri = "https://example.com/path#section";
    const result = splitUri(uri);

    try std.testing.expectEqualStrings("https://", result.scheme.?);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("example.com/", iter.next().?);
    try std.testing.expectEqualStrings("path#", iter.next().?);
    try std.testing.expectEqualStrings("section", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_uri_with_query_and_fragment" {
    const uri = "https://example.com/path?query=value#section";
    const result = splitUri(uri);

    try std.testing.expectEqualStrings("https://", result.scheme.?);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("example.com/", iter.next().?);
    try std.testing.expectEqualStrings("path?", iter.next().?);
    try std.testing.expectEqualStrings("query=value#", iter.next().?);
    try std.testing.expectEqualStrings("section", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_path_with_query_params" {
    const uri = "/path/to/file?param=value";
    const result = splitUri(uri);

    try std.testing.expect(result.scheme == null);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("/", iter.next().?);
    try std.testing.expectEqualStrings("path/", iter.next().?);
    try std.testing.expectEqualStrings("to/", iter.next().?);
    try std.testing.expectEqualStrings("file?", iter.next().?);
    try std.testing.expectEqualStrings("param=value", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "split_path_with_fragment" {
    const uri = "/path/to/file#anchor";
    const result = splitUri(uri);

    try std.testing.expect(result.scheme == null);

    var iter = result.iterator();
    try std.testing.expectEqualStrings("/", iter.next().?);
    try std.testing.expectEqualStrings("path/", iter.next().?);
    try std.testing.expectEqualStrings("to/", iter.next().?);
    try std.testing.expectEqualStrings("file#", iter.next().?);
    try std.testing.expectEqualStrings("anchor", iter.next().?);
    try std.testing.expect(iter.next() == null);
}

test "xor_in_place" {
    var data = [_]u8{ 0xFF, 0x00, 0xAA, 0x55 };
    const keystream = [_]u8{ 0x00, 0xFF, 0x55, 0xAA };
    xorInPlace(&data, &keystream);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF }, &data);
}

test "encrypt_decrypt_basic" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com";
    const secret_key = "test_key";
    const context = "test_context";

    const encrypted = try encryptUri(allocator, uri, secret_key, context);
    defer allocator.free(encrypted);

    // Check that scheme is preserved
    try std.testing.expect(std.mem.startsWith(u8, encrypted, "https://"));

    const decrypted = try decryptUri(allocator, encrypted, secret_key, context);
    defer allocator.free(decrypted);

    try std.testing.expectEqualStrings(uri, decrypted);
}

test "encrypt_deterministic" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com/test";
    const secret_key = "my_secret";
    const context = "test_ctx";

    const encrypted1 = try encryptUri(allocator, uri, secret_key, context);
    defer allocator.free(encrypted1);
    const encrypted2 = try encryptUri(allocator, uri, secret_key, context);
    defer allocator.free(encrypted2);

    // Same input should produce same output
    try std.testing.expectEqualStrings(encrypted1, encrypted2);
}

test "encrypt_different_keys" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com";
    const key1 = "key1";
    const key2 = "key2";
    const context = "test_ctx";

    const encrypted1 = try encryptUri(allocator, uri, key1, context);
    defer allocator.free(encrypted1);
    const encrypted2 = try encryptUri(allocator, uri, key2, context);
    defer allocator.free(encrypted2);

    // Different keys should produce different outputs
    try std.testing.expect(!std.mem.eql(u8, encrypted1, encrypted2));
}

test "round_trip_various_uris" {
    const allocator = std.testing.allocator;

    const test_cases = [_][]const u8{
        "https://example.com",
        "https://example.com/",
        "https://example.com/path",
        "https://example.com/path/",
        "https://example.com/a/b/c/d/e",
        "https://subdomain.example.com/path/to/resource",
        // URIs with query parameters
        "https://example.com?query=value",
        "https://example.com/path?foo=bar",
        "https://example.com/path?foo=bar&baz=qux",
        "https://example.com/path/file?param1=value1&param2=value2",
        // URIs with fragments
        "https://example.com#section",
        "https://example.com/path#heading",
        "https://example.com/path/file#anchor",
        // URIs with both query and fragment
        "https://example.com?query=value#section",
        "https://example.com/path?foo=bar#heading",
        "https://example.com/path/file?param1=value1&param2=value2#anchor",
    };

    const secret_key = "my_secret_key";
    const context = "test_context";

    for (test_cases) |uri| {
        const encrypted = try encryptUri(allocator, uri, secret_key, context);
        defer allocator.free(encrypted);
        const decrypted = try decryptUri(allocator, encrypted, secret_key, context);
        defer allocator.free(decrypted);
        try std.testing.expectEqualStrings(uri, decrypted);
    }
}

test "decrypt_wrong_key" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com";
    const encrypt_key = "key1";
    const decrypt_key = "key2";
    const context = "test_context";

    const encrypted = try encryptUri(allocator, uri, encrypt_key, context);
    defer allocator.free(encrypted);

    const result = decryptUri(allocator, encrypted, decrypt_key, context);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "decrypt_wrong_context" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com";
    const secret_key = "test_key";
    const context1 = "context1";
    const context2 = "context2";

    const encrypted = try encryptUri(allocator, uri, secret_key, context1);
    defer allocator.free(encrypted);

    const result = decryptUri(allocator, encrypted, secret_key, context2);
    try std.testing.expectError(error.DecryptionFailed, result);
}

test "path_only_encryption" {
    const allocator = std.testing.allocator;

    const secret_key = "test_key";
    const context = "test_context";

    // Test absolute path
    const path1 = "/path/to/file";
    const encrypted1 = try encryptUri(allocator, path1, secret_key, context);
    defer allocator.free(encrypted1);

    // Should start with '/' followed by base64
    try std.testing.expect(std.mem.startsWith(u8, encrypted1, "/"));
    try std.testing.expect(std.mem.indexOf(u8, encrypted1, "://") == null);

    // Should decrypt correctly
    const decrypted1 = try decryptUri(allocator, encrypted1, secret_key, context);
    defer allocator.free(decrypted1);
    try std.testing.expectEqualStrings(path1, decrypted1);

    // Test relative path
    const path2 = "path/to/file";
    const encrypted2 = try encryptUri(allocator, path2, secret_key, context);
    defer allocator.free(encrypted2);

    try std.testing.expect(std.mem.startsWith(u8, encrypted2, "/"));

    const decrypted2 = try decryptUri(allocator, encrypted2, secret_key, context);
    defer allocator.free(decrypted2);
    try std.testing.expectEqualStrings(path2, decrypted2);
}

test "keys_with_identical_halves_work" {
    const allocator = std.testing.allocator;

    const uri = "https://example.com/path";
    const identical_halves_key = "same_halfsame_half"; // Both halves are identical
    const context = "test";

    // Should work fine now that validation is removed
    const encrypted = try encryptUri(allocator, uri, identical_halves_key, context);
    defer allocator.free(encrypted);
    try std.testing.expect(encrypted.len > 0);

    // Should decrypt successfully
    const decrypted = try decryptUri(allocator, encrypted, identical_halves_key, context);
    defer allocator.free(decrypted);
    try std.testing.expectEqualStrings(uri, decrypted);
}
