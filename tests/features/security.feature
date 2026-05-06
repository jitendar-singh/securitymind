Feature: Security Hardening
  Security controls protect cookies, tokens, and secrets.

  Scenario: Logout revokes the JWT so it cannot be reused
    Given I am logged in as "revoke-test@example.com" with password "Secret99!"
    And I save my current session cookie
    When I log out
    And I restore my saved session cookie
    And I request my profile
    Then the response status should be 401

  Scenario: Session cookie is not marked Secure in development
    Given the environment is "development"
    When I sign up with email "dev-cookie@example.com" password "Secret99!" and name "Dev"
    Then the response status should be 200
    And the session cookie should not have the Secure flag

  Scenario: Session cookie is marked Secure in production
    Given the environment is "production"
    When I sign up with email "prod-cookie@example.com" password "Secret99!" and name "Prod"
    Then the response status should be 200
    And the session cookie should have the Secure flag
