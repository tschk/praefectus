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
    NSPredicate *visibleIcon = [NSPredicate predicateWithBlock:^BOOL(id object, NSDictionary *bindings) {
        for (XCUIElement *icon in springboard.icons.allElementsBoundByIndex) {
            if (icon.hittable) {
                return YES;
            }
        }
        return NO;
    }];
    XCTNSPredicateExpectation *iconResult = [[XCTNSPredicateExpectation alloc] initWithPredicate:visibleIcon
                                                                                      object:springboard];
    XCTAssertEqual([XCTWaiter waitForExpectations:@[iconResult] timeout:5], XCTWaiterResultCompleted);
}

@end
