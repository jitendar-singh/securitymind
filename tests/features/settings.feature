Feature: Model Settings
  Users can view and change per-agent model selections.

  Scenario: Get default model selections
    Given I am logged in as "settings-user@example.com" with password "Secret99!"
    When I get model settings
    Then the response status should be 200
    And the response JSON should have key "agents"
    And the response JSON should have key "selections"

  Scenario: Update model selection
    Given I am logged in as "settings-put@example.com" with password "Secret99!"
    When I set model for agent "secmind" to "gemini-2.5-flash"
    Then the response status should be 200

  Scenario: Update with unknown agent ID
    Given I am logged in as "settings-bad@example.com" with password "Secret99!"
    When I set model for agent "nonexistent_agent" to "gemini-2.5-flash"
    Then the response status should be 400
    And the response JSON at "error" should contain "Unknown agent"

  Scenario: Get settings without auth
    When I get model settings without a session
    Then the response status should be 401

  Scenario: Update settings without auth
    When I update model settings without a session
    Then the response status should be 401
