import XCTest

final class AppUITests: XCTestCase {
    func testSetupRefusesUnpairedExecutionAndShowsOperationFields() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["phone-status"].waitForExistence(timeout: 10))
        capture("01-unpaired")
        XCTAssertFalse(app.buttons["Discover services and apps"].isEnabled)
        app.buttons["Connect to this iPhone"].tap()
        XCTAssertTrue(app.staticTexts["A pairing record and valid RemotePairing port are required."].exists)
        capture("02-missing-pairing")
        app.swipeUp()
        let confirmation = app.switches["Confirm each action"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 5))
        XCTAssertEqual(confirmation.value as? String, "0")
        capture("03-session-default")
        confirmation.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        XCTAssertEqual(confirmation.value as? String, "1")
        capture("04-opt-in-confirmation")
        confirmation.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)).tap()
        XCTAssertEqual(confirmation.value as? String, "0")
        let picker = app.buttons["operation-picker"]
        XCTAssertTrue(picker.waitForExistence(timeout: 5))
        picker.tap()
        app.buttons["Swipe"].tap()
        XCTAssertTrue(app.textFields["End X"].exists)
        XCTAssertTrue(app.textFields["End Y"].exists)
        capture("03-swipe-fields")
        picker.tap()
        app.buttons["Paste text"].tap()
        XCTAssertTrue(app.textFields["Text to paste (replaces clipboard)"].exists)
        XCTAssertFalse(app.textFields["End X"].exists)
        capture("04-paste-fields")
        picker.tap()
        app.buttons["Launch app"].tap()
        XCTAssertTrue(app.textFields["Bundle identifier"].exists)
        XCTAssertFalse(app.textFields["X (screenshot pixels)"].exists)
        XCTAssertFalse(app.buttons["Run after 3 seconds"].isEnabled)
        capture("05-launch-fields")
    }

    private func capture(_ name: String) {
        let attachment = XCTAttachment(screenshot: XCUIScreen.main.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
