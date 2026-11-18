// ISC. Test-only adapter to the installed Apple framework, not a reimplementation.
// Fresh in-memory identities only; no pairing daemon, Keychain, or real device is used.
#import <Foundation/Foundation.h>
#import <dlfcn.h>

@interface NSObject (PairingTest)
- (void)setRandomKeyPair;
- (void)activate;
- (void)receivedData:(NSData *)data;
- (int)deriveKeyWithSaltPtr:(const void *)salt saltLen:(size_t)saltLen
    infoPtr:(const void *)info infoLen:(size_t)infoLen keyLen:(size_t)keyLen outputKeyPtr:(void *)output;
@end

int main(int argc, const char **argv) { @autoreleasepool {
    if (argc != 4 || !dlopen("/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils", RTLD_NOW)) return 2;
    BOOL setup = strcmp(argv[1], "setup") == 0;
    NSString *hostID = [NSString stringWithUTF8String:argv[2]];
    NSData *hostKey = [[NSData alloc] initWithBase64EncodedString:[NSString stringWithUTF8String:argv[3]] options:0];
    id identity = [NSClassFromString(@"CUPairingIdentity") new];
    [identity setRandomKeyPair];
    [identity setValue:[[NSUUID alloc] initWithUUIDString:@"D733FF81-410B-4F4D-9836-A963FD2C844B"] forKey:@"identifier"];
    id session = [NSClassFromString(@"CUPairingSession") new];
    [session setValue:@(setup ? 2 : 4) forKey:@"sessionType"];
    [session setValue:@4 forKey:@"flags"]; // caller-supplied in-memory identity and peer callbacks
    [session setValue:dispatch_get_main_queue() forKey:@"dispatchQueue"];
    [session setValue:@"000000" forKey:@"fixedPIN"];
    [session setValue:@{@"altIRK": [NSMutableData dataWithLength:16], @"accountID": @"test-device",
        @"model": @"TestDevice", @"name": @"Test", @"remotepairing_udid": @"test-udid"} forKey:@"additionalSelfInfo"];
    [session setValue:^id(NSUInteger options, NSError **error) { return identity; } forKey:@"copyIdentityHandler"];
    [session setValue:^id(id identifier, NSUInteger options, NSError **error) {
        id peer = [NSClassFromString(@"CUPairedPeer") new];
        [peer setValue:[[NSUUID alloc] initWithUUIDString:hostID] forKey:@"identifier"];
        [peer setValue:hostKey forKey:@"publicKey"];
        return peer;
    } forKey:@"findPeerHandler"];
    [session setValue:^(id peer, NSUInteger options, NSError **error) {} forKey:@"savePeerHandler"];
    [session setValue:^(id pin) {} forKey:@"showPINHandler"];
    [session setValue:^(NSUInteger flags, NSData *data) {
        printf("TLV %s\n", [data base64EncodedStringWithOptions:0].UTF8String); fflush(stdout);
    } forKey:@"sendDataHandler"];
    __weak id weakSession = session;
    [session setValue:^(NSError *error) {
        if (error) { puts("FAILED"); fflush(stdout); return; }
        uint8_t key[32];
        const char *info = "ServerEncrypt-main";
        int status = [weakSession deriveKeyWithSaltPtr:NULL saltLen:0 infoPtr:info infoLen:strlen(info) keyLen:32 outputKeyPtr:key];
        if (status) { puts("FAILED"); } else {
            printf("DONE %s\n", [[NSData dataWithBytes:key length:32] base64EncodedStringWithOptions:0].UTF8String);
        }
        fflush(stdout);
    } forKey:@"completionHandler"];
    printf("PUB %s\n", [[identity valueForKey:@"publicKey"] base64EncodedStringWithOptions:0].UTF8String); fflush(stdout);
    [session activate];
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{ exit(3); });
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        char *line = NULL; size_t capacity = 0;
        while (getline(&line, &capacity, stdin) > 0) {
            NSString *encoded = [[NSString alloc] initWithUTF8String:line];
            NSData *data = [[NSData alloc] initWithBase64EncodedString:[encoded stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] options:0];
            dispatch_async(dispatch_get_main_queue(), ^{ [session receivedData:data]; });
        }
        free(line);
        dispatch_async(dispatch_get_main_queue(), ^{ exit(0); });
    });
    dispatch_main();
} }
