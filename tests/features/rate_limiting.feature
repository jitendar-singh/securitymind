Feature: Rate Limiting
  Auth endpoints are rate-limited to prevent brute-force attacks.

  Scenario: Login rate limit after 10 attempts
    Given a user exists with email "victim@example.com" and password "Secret99!"
    When I attempt to log in 11 times with email "victim@example.com" and password "wrong"
    Then the first 10 responses should have status 401
    And the 11th response should have status 429

  Scenario: Signup rate limit after 5 attempts
    When I attempt to sign up 6 times with email "spam@example.com"
    Then the first 5 responses should have status 200 or 400
    And the 6th response should have status 429
