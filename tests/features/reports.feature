Feature: Reports
  Users can list and download generated security reports.

  Scenario: List reports when no reports exist
    Given I am logged in as "reports-empty@example.com" with password "Secret99!"
    And the reports directory is isolated
    When I list reports
    Then the response status should be 200
    And the response should be a list of length 0

  Scenario: List reports with files on disk
    Given I am logged in as "reports-list@example.com" with password "Secret99!"
    And a compliance report file exists for the current user
    When I list reports
    Then the response status should be 200
    And the response should be a list of length 1
    And the first report should have type "cloud_compliance"

  Scenario: Download a report
    Given I am logged in as "reports-dl@example.com" with password "Secret99!"
    And a compliance report file exists for the current user
    When I download report "compliance_report_test_project.html"
    Then the response status should be 200

  Scenario: Download nonexistent report
    Given I am logged in as "reports-miss@example.com" with password "Secret99!"
    When I download report "nonexistent.html"
    Then the response status should be 404

  Scenario: Path traversal is rejected
    Given I am logged in as "reports-traversal@example.com" with password "Secret99!"
    When I download report "../etc/passwd"
    Then the response status should be 404
