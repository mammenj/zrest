const std = @import("std");
// const dns = @import("dns.zig"); // Assuming you have milo-g/zigdns installed
const dns = @import("zig_dns");
// --- 1. Define the Validation Rule Interface ---

/// Common error set for all email validation errors.
pub const EmailValidationError = error{
    // Format errors
    InvalidFormat,
    MissingAtSymbol,
    MissingDomain,
    MissingTopLevelDomain,
    InvalidCharacters,
    TooLong, // Example for future length checks

    // DNS/MX errors
    DomainNotFound, // Could be DNS resolution failure for A/AAAA
    NoMxRecords,
    MxResolutionFailed, // Error during MX lookup
    DnsLookupFailed, // General DNS lookup error

    // Other potential errors
    AllocationFailed,
    RegexError,
    // Add more specific errors as needed
};

/// Type alias for a validation rule function.
/// Each rule takes the email string and an allocator,
/// and returns !void on success, or an EmailValidationError on failure.
// pub const ValidationRule = fn (allocator: std.mem.Allocator, email: []const u8) EmailValidationError!void;
pub const ValidationRule = *const fn (allocator: std.mem.Allocator, email: []const u8) EmailValidationError!void;
// --- 2. Implement Specific Validation Rules ---

/// Rule 1: Basic structural format checks (contains '@', has domain, has TLD)
pub fn validateFormatBasic(allocator: std.mem.Allocator, email: []const u8) EmailValidationError!void {
    _ = allocator; // Unused, but keeps signature consistent

    if (email.len == 0) return EmailValidationError.InvalidFormat;

    const at_index = std.mem.indexOf(u8, email, "@") orelse return EmailValidationError.MissingAtSymbol;
    if (at_index == 0) return EmailValidationError.InvalidFormat; // No local part

    const domain_part = email[at_index + 1 ..];
    if (domain_part.len == 0) return EmailValidationError.MissingDomain; // No domain part

    const dot_index = std.mem.indexOf(u8, domain_part, ".") orelse return EmailValidationError.MissingTopLevelDomain;
    if (dot_index == 0 or dot_index == domain_part.len - 1) {
        return EmailValidationError.MissingTopLevelDomain; // Domain starts/ends with dot, or no TLD
    }

    // Basic character set check (can be improved with regex)
    for (email) |c| {
        if (!((c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or
            (c >= '0' and c <= '9') or
            c == '.' or c == '-' or c == '_' or c == '@' or c == '+'))
        {
            // This is a very simplistic check. A real regex is needed.
            // For now, allow a common set of characters.
            return EmailValidationError.InvalidCharacters;
        }
    }
}

/// Rule 2: Regex-based format validation (requires zig-regex)
/// IMPORTANT: This regex is a common, but not fully RFC-compliant, pattern.
/// Full RFC-compliant regex is extremely complex.
// pub fn validateFormatRegex(allocator: std.mem.Allocator, email: []const u8) EmailValidationError!void {
//     const email_regex_pattern =
//         "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
//
//     var regex: Regex = undefined;
//     errdefer regex.deinit(); // Ensure deinit is called if init fails
//
//     // Initialize the regex engine
//     // Note: Regex.init might require an allocator depending on its implementation
//     regex = try Regex.init(allocator, email_regex_pattern) catch |err| {
//         std.debug.print("Regex init error: {any}\n", .{err});
//         return EmailValidationError.RegexError;
//     };
//
//     if (!regex.matches(email)) {
//         return EmailValidationError.InvalidFormat;
//     }
// }

/// Rule 3: DNS Domain Existence (A or AAAA record lookup)
/// This checks if the domain actually resolves to an IP address.
/// Rule 4: MX Record Existence (Mail Exchange records)
pub fn validateMxRecords(allocator: std.mem.Allocator, email: []const u8) EmailValidationError!void {
    const at_idx = std.mem.lastIndexOfScalar(u8, email, '@') orelse return EmailValidationError.InvalidFormat;
    const domain = email[(at_idx + 1)..];
    // Build DNS query packet
    var message = try dns.createQuery(allocator, domain, dns.QType.MX);
    defer message.deinit();

    // Send via UDP
    try std.net.init();
    const sock = try std.net.udpSocket(allocator, .{});
    defer sock.close();
    const resolver = "8.8.8.8:53";
    _ = try sock.sendTo(resolver, message.to_bytes(allocator));

    var buf: [512]u8 = undefined;
    const n = try sock.recvFrom(&buf);
    const response = try dns.Message.from_bytes(allocator, buf[0..n]);
    defer response.deinit();

    if (response.answers.len == 0) {
        return EmailValidationError.NoMx;
    }
}
// --- 3. Create the Pluggable Validator Struct ---

pub const EmailValidator = struct {
    allocator: std.mem.Allocator,
    rules: []const ValidationRule, // <- FIXED HERE

    pub fn init(allocator: std.mem.Allocator, rules: []const ValidationRule) EmailValidator {
        return .{
            .allocator = allocator,
            .rules = rules,
        };
    }

    pub fn validate(self: EmailValidator, email: []const u8) EmailValidationError!void {
        for (self.rules) |rule_fn| {
            try rule_fn(self.allocator, email);
        }
    }
};
// --- 4. Example Usage in main ---

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Define the set of validation rules you want to use
    // You can mix and match these, or create new ones.
    const strict_rules = &[_]ValidationRule{
        validateFormatBasic,
        //validateMxRecords,
    };
    // const basic_rules = [_]ValidationRule{
    // validateFormatBasic,
    // No DNS lookups for faster basic validation
    // };

    // Create validator instances
    const strict_validator = EmailValidator.init(allocator, strict_rules);
    // const basic_validator = EmailValidator.init(allocator, &basic_rules);

    // Test cases
    const emails = [_][]const u8{
        "test@example.com", // Should pass all if example.com has MX
        "valid@gmail.com", // Should pass all
        "invalid-format", // Fails format
        "no@domain", // Fails TLD
        "no.mx@nonexistentdomain1234567890.com", // Fails MX
        "test@localhost", // Fails DNS
        "another@a.b.c", // Passes basic, might fail DNS
        "user@sub.domain.co.uk", // Complex but valid format
        "with+alias@example.com", // Valid format
        "badchars!@example.com", // Fails InvalidCharacters if strict regex
    };

    std.debug.print("\n--- Running Strict Validation ---\n", .{});
    for (emails) |email| {
        std.debug.print("Validating '{s}': ", .{email});
        if (strict_validator.validate(email)) {
            std.debug.print("OK\n", .{});
        } else |err| {
            std.debug.print("FAILED: {any}\n", .{err});
        }
    }

    // std.debug.print("\n--- Running Basic Validation ---\n", .{});
    // for (emails) |email| {
    // std.debug.print("Validating '{s}': ", .{email});
    // if (basic_validator.validate(email)) {
    // std.debug.print("OK\n", .{});
    // } else |err| {
    // std.debug.print("FAILED: {any}\n", .{err});
    // }
    // }
}
