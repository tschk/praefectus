#import <XCTest/XCTest.h>

@interface HomeValidation : XCTestCase
@end

@implementation HomeValidation

- (void)testHomeOnce {
    self.continueAfterFailure = NO;
    XCUIApplication *settings = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.Preferences"];
    XCUIApplication *springboard = [[XCUIApplication alloc] initWithBundleIdentifier:@"com.apple.springboard"];
    [settings activate];
    XCTAssertEqual(settings.state, XCUIApplicationStateRunningForeground,
                   @"Settings must be in the foreground before the Home event.");

    [[XCUIDevice sharedDevice] pressButton:XCUIDeviceButtonHome];

    NSPredicate *foreground = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        return springboard.state == XCUIApplicationStateRunningForeground;
    }];
    XCTNSPredicateExpectation *result = [[XCTNSPredicateExpectation alloc] initWithPredicate:foreground
                                                                                  object:springboard];
    XCTAssertEqual([XCTWaiter waitForExpectations:@[result] timeout:5], XCTWaiterResultCompleted);
    XCTAssertNotEqual(settings.state, XCUIApplicationStateRunningForeground);
    XCTAssertTrue([springboard.icons.firstMatch waitForExistenceWithTimeout:5]);
}

@end
