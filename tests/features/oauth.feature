Feature: OAuth Error Handling
  Google OAuth callback rejects invalid requests.

  Scenario: Callback with error parameter
    When I call the OAuth callback with error "access_denied"
    Then the response status should be 400
    And the response JSON at "error" should contain "access_denied"

  Scenario: Callback with state mismatch
    When I call the OAuth callback with code "abc" and state "wrong-state"
    Then the response status should be 400
    And the response JSON at "error" should contain "state mismatch"

  Scenario: Callback with missing code
    When I call the OAuth callback with no code
    Then the response status should be 400
    And the response JSON at "error" should contain "missing code"
