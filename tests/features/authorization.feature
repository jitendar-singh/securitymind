Feature: Authorization Guards
  All protected routes return 401 without a valid session.

  Scenario: GET /auth/me without auth
    When I make an unauthenticated GET to "/auth/me"
    Then the response status should be 401

  Scenario: POST /chat without auth
    When I make an unauthenticated POST to "/chat"
    Then the response status should be 401

  Scenario: GET /integrations without auth
    When I make an unauthenticated GET to "/integrations"
    Then the response status should be 401

  Scenario: POST /integrations without auth
    When I make an unauthenticated POST to "/integrations"
    Then the response status should be 401

  Scenario: GET /integrations/1 without auth
    When I make an unauthenticated GET to "/integrations/1"
    Then the response status should be 401

  Scenario: PUT /integrations/1 without auth
    When I make an unauthenticated PUT to "/integrations/1"
    Then the response status should be 401

  Scenario: DELETE /integrations/1 without auth
    When I make an unauthenticated DELETE to "/integrations/1"
    Then the response status should be 401

  Scenario: POST /integrations/1/test without auth
    When I make an unauthenticated POST to "/integrations/1/test"
    Then the response status should be 401

  Scenario: GET /settings/models without auth
    When I make an unauthenticated GET to "/settings/models"
    Then the response status should be 401

  Scenario: PUT /settings/models without auth
    When I make an unauthenticated PUT to "/settings/models"
    Then the response status should be 401

  Scenario: GET /reports without auth
    When I make an unauthenticated GET to "/reports"
    Then the response status should be 401

  Scenario: GET /reports/somefile.html without auth
    When I make an unauthenticated GET to "/reports/somefile.html"
    Then the response status should be 401
