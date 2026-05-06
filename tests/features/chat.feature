Feature: Chat
  Authenticated users can send messages to the security agent.

  Scenario: Send a message while authenticated
    Given I am logged in as "user1@example.com" with password "Secret99!"
    When I send a chat message "What vulnerabilities exist?"
    Then the response status should be 200
    And the response JSON should have key "response"
    And the response JSON should have key "agent"

  Scenario: Send a message without authentication
    When I send a chat message "hello" without a session
    Then the response status should be 401

  Scenario: Send an empty message
    Given I am logged in as "user2@example.com" with password "Secret99!"
    When I send a chat message ""
    Then the response status should be 400
    And the response JSON at "error" should contain "No message"
