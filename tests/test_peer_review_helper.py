import pytest
from peer_review_helper import PlexTracAPI  # Import your main script
from pytest_mock import MockerFixture

# UNDER CONSTRUCTION - NOT FOR CURRENT USE

# Mock Data Fixtures
@pytest.fixture
def api_instance(mocker):
    """Create an API instance with mock data (disables real API calls)."""
    api = PlexTracAPI('fake', 'fake', 'fake')

    api.client_id=None
    api.report_id=None
    api.token="test"
    api.client=None

    def mock_request(method, url, headers=None, params=None, data=None, json=None):
        """Mock API request handling for testing."""
        # Get a specific finding
        if method == "GET" and "report/" in url and "client/" in url and "flaw/" in url:
            return mocker.Mock(status_code=200, json=lambda: {
             
            })
        # Get brief info on a list of findings
        elif method == "GET" and "report/" in url and "client/" in url and "/flaws" in url:
            return mocker.Mock(status_code=200, json=lambda: [
                {
            }
            ])
        # Retrieve the Clients list
        elif method == "GET" and "client/list" in url:
            return mocker.Mock(status_code=200, json=lambda: [
              {
                "id": "client_1045",
                "doc_id": [
                  1045
                ],
                "data": [
                  1045,
                  "Karbo Industries",
                  None
                ]
              }
            ]
            )
        # Retrieve the list of reports
        elif method == "GET" and "reports" in url:
            return mocker.Mock(status_code=200, json=lambda: [
              {
          
              }
            ]
            )
        # Get a specific report
        elif method == "GET" and "report/" in url and "client/" in url:
            return mocker.Mock(status_code=200, json=lambda: {
     
            )
        elif method == "PUT" and "report/" in url and "client/" in url and "flaw/" in url:
            return mocker.Mock(status_code=200, json=lambda: {
                })  # Mock successful update
        elif method == "PUT" and "report/" in url and "client/" in url:
            return mocker.Mock(status_code=200, json=lambda: {
  
            })
        return mocker.Mock(status_code=404, json=lambda: {})


     # Patch make_request_authenticated to use our mock_request function
    mocker.patch.object(api, "make_request_authenticated", side_effect=mock_request)

    return api

def test_get_client(api_instance):
    """Ensure report fetching works with mock data."""
    client = api_instance.get_client("Karbo Industries")
    assert client is not None and client["data"][1].lower() == "karbo industries"


def test_get_report(api_instance):
    """Ensure report fetching works with mock data."""
    report = api_instance.get_report("Karbo Industries", "report Title")
    assert report is not None and str(report["id"]) == "959987286"
    assert report is not None and report["name"] == "New Test Report"

def test_get_report_findings_list(api_instance):
    """Ensure report fetching works with mock data."""
    report_findings_list = api_instance.get_report_findings_list("Karbo Industries", "report Title")
    print(report_findings_list)
    assert report_findings_list is not None and str(report_findings_list[0]["id"]) == "flaw_1963-500009-2948506292"

@pytest.mark.parametrize("field, new_value", [
    ("updated_text", "new exec summary")
])
def test_update_executive_summary(api_instance, field, new_value):
    """Ensure executive summary updates correctly in dry-run mode."""
    
    api_instance.get_report("Karbo Industries", "report Title")
    result = api_instance.update_executive_summary("clx0lzynj003e0ho448ddh4ml", **{field: new_value})
    assert result is True

@pytest.mark.parametrize("field, new_value", [
    ("updated_title", "New Finding Title"),
    ("updated_description", "New Finding Description"),
    ("updated_recommendations", "New Finding Recommendations")
])
def test_update_finding(api_instance, field, new_value):
    """Test updating different parts of a finding in dry-run mode."""

    api_instance.get_report("Karbo Industries", "report Title")
    api_instance.get_report_findings_list("Karbo Industries", "report Title")
    api_instance.get_report_findings_content("Karbo Industries", "report Title")
    # Call update_finding with only the field being tested
    result = api_instance.update_finding("2948506292", **{field: new_value})

    # Ensure the update was successful
    assert result is True


def test_check_if_report_has_duplicate(api_instance):
    """Ensure duplicate report detection works case-insensitively."""
    api_instance.reports=[
              {
   
              }
            ]
    assert api_instance.check_if_report_has_duplicate("Report Title") is True
    assert api_instance.check_if_report_has_duplicate("report title") is True
    assert api_instance.check_if_report_has_duplicate("2") is False

def test_generate_visual_reportdiff(api_instance):
    """Ensure visual diff is generated correctly."""
    api_instance.suggestedfixes_from_llm = {
        "executive_summary_custom_fields": {"custom_fields": [{"id": "123", "text": "New Summary"}]},
        "findings": [
            {"id": "1", "title": "New Title", "description": "New Desc", "recommendations": "New Rec"}
        ]
    }
    diff = api_instance.generate_visual_reportdiff()
    assert isinstance(diff, list)
    assert len(diff) > 0  # Diff should contain changes
