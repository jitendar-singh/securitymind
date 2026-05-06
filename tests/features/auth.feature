Feature: Authentication
  Users can sign up, log in, check their session, and log out.

  Scenario: Successful signup
    When I sign up with email "alice@example.com" password "Secret99!" and name "Alice"
    Then the response status should be 200
    And the response JSON should have key "user"
    And the response JSON at "user.email" should be "alice@example.com"
    And a session cookie should be set

  Scenario: Signup with duplicate email
    Given a user exists with email "bob@example.com" and password "Secret99!"
    When I sign up with email "bob@example.com" password "Other1234!" and name "Bob2"
    Then the response status should be 400
    And the response JSON at "error" should contain "already exists"

  Scenario: Signup with missing password
    When I sign up with email "no-pass@example.com" password "" and name "NoPass"
    Then the response status should be 400

  Scenario: Signup with short password
    When I sign up with email "short@example.com" password "abc" and name "Short"
    Then the response status should be 400

  Scenario: Signup with invalid email
    When I sign up with email "not-an-email" password "Secret99!" and name "Bad"
    Then the response status should be 400

  Scenario: Successful login
    Given a user exists with email "carol@example.com" and password "Secret99!"
    When I log in with email "carol@example.com" and password "Secret99!"
    Then the response status should be 200
    And the response JSON should have key "user"
    And a session cookie should be set

  Scenario: Login with wrong password
    Given a user exists with email "dave@example.com" and password "Secret99!"
    When I log in with email "dave@example.com" and password "WrongPass1!"
    Then the response status should be 401

  Scenario: Login with nonexistent email
    When I log in with email "ghost@example.com" and password "Secret99!"
    Then the response status should be 401

  Scenario: Check session with valid cookie
    Given I am logged in as "eve@example.com" with password "Secret99!"
    When I request my profile
    Then the response status should be 200
    And the response JSON at "user.email" should be "eve@example.com"

  Scenario: Check session without cookie
    When I request my profile without a session
    Then the response status should be 401

  Scenario: Logout clears session
    Given I am logged in as "frank@example.com" with password "Secret99!"
    When I log out
    Then the response status should be 200
    When I request my profile
    Then the response status should be 401
