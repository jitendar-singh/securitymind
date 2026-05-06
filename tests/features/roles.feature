Feature: Role Assignment and Orphan Claims
  The first user gets admin role. Admin claims orphan integrations.

  Scenario: First signup gets admin role
    When I sign up with email "first@example.com" password "Secret99!" and name "First"
    Then the response status should be 200
    And the response JSON at "user.role" should be "admin"

  Scenario: Second signup gets user role
    Given a user exists with email "admin@example.com" and password "Secret99!"
    When I sign up with email "second@example.com" password "Secret99!" and name "Second"
    Then the response status should be 200
    And the response JSON at "user.role" should be "user"

  Scenario: First admin claims orphan integrations
    Given orphan integrations exist in the store
    When I sign up with email "claim-admin@example.com" password "Secret99!" and name "Admin"
    Then the response status should be 200
    When I list my integrations
    Then the response should be a list of length 1
