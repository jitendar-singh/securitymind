Feature: Integration Connection Test
  Users can test whether their stored integration credentials are valid.

  Scenario: Test connection for nonexistent integration
    Given I am logged in as "testconn@example.com" with password "Secret99!"
    When I test connection for integration 999
    Then the response status should be 404

  Scenario: Test connection returns provider result
    Given I am logged in as "testconn2@example.com" with password "Secret99!"
    And I have created an integration with provider "nvd" and name "default"
    And the connection tester is mocked to return success
    When I test connection for integration 1
    Then the response status should be 200
    And the response JSON at "status" should be "success"
