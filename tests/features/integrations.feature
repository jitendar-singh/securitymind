Feature: Integrations CRUD
  Authenticated users manage their encrypted integration credentials.

  Scenario: Create an integration
    Given I am logged in as "integ-user@example.com" with password "Secret99!"
    When I create an integration with provider "jira" name "main" and config:
      | key        | value                    |
      | JIRA_URL   | https://jira.example.com |
      | JIRA_USER  | me@co.com                |
      | JIRA_TOKEN | tok123                   |
    Then the response status should be 201
    And the response JSON at "provider" should be "jira"
    And the response JSON at "name" should be "main"
    And the response JSON should have key "fields"
    And the response JSON should not have key "config"

  Scenario: List integrations returns only current user's records
    Given I am logged in as "list-user@example.com" with password "Secret99!"
    And I have created an integration with provider "nvd" and name "default"
    When I list my integrations
    Then the response status should be 200
    And the response should be a list of length 1

  Scenario: Get integration by ID
    Given I am logged in as "get-user@example.com" with password "Secret99!"
    And I have created an integration with provider "github" and name "main"
    When I get integration 1
    Then the response status should be 200
    And the response JSON at "provider" should be "github"

  Scenario: Cannot access another user's integration
    Given I am logged in as "owner@example.com" with password "Secret99!"
    And I have created an integration with provider "jira" and name "mine"
    When I log out
    And I sign up and log in as "intruder@example.com" with password "Secret99!"
    And I get integration 1
    Then the response status should be 404

  Scenario: Update integration name
    Given I am logged in as "update-user@example.com" with password "Secret99!"
    And I have created an integration with provider "aws" and name "old-name"
    When I update integration 1 with name "new-name"
    Then the response status should be 200
    And the response JSON at "name" should be "new-name"

  Scenario: Delete integration
    Given I am logged in as "del-user@example.com" with password "Secret99!"
    And I have created an integration with provider "gcp" and name "test"
    When I delete integration 1
    Then the response status should be 204
    When I get integration 1
    Then the response status should be 404

  Scenario: Delete nonexistent integration
    Given I am logged in as "del-miss@example.com" with password "Secret99!"
    When I delete integration 999
    Then the response status should be 404

  Scenario: Create duplicate provider/name
    Given I am logged in as "dup-user@example.com" with password "Secret99!"
    And I have created an integration with provider "jira" and name "main"
    When I create an integration with provider "jira" name "main" and config:
      | key        | value |
      | JIRA_TOKEN | x     |
    Then the response status should be 409

  Scenario: Create integration with missing fields
    Given I am logged in as "bad-user@example.com" with password "Secret99!"
    When I create an integration with empty provider and name
    Then the response status should be 400
