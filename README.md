import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from app.main import app   # <-- update this if your fastAPI app is located elsewhere

client = TestClient(app)


# -------------------------------------------------------------
# TEST 1: Successful flow (Controller returns valid result_state)
# -------------------------------------------------------------
@patch("app.service_generation_service.DataAccessTool")
@patch("app.service_generation_service.Controller")
def test_testscript_generation_success(mock_controller, mock_data_access):

    # Mock controller.run()
    controller_instance = MagicMock()
    controller_instance.run.return_value = {
        "generated_code": "print('Hello')",
        "error_message": "",
        "execution_status": "success",
        "prompt_validation_results": {"passed": True},
        "swagger_schema_validation_passed": True,
        "url_validation_passed": True
    }
    mock_controller.return_value = controller_instance

    # Mock DB insert to always succeed
    mock_data_access.return_value.db_operation.return_value = True

    request_body = {
        "request_id": "REQ-101",
        "userName": "Tester1",
        "input_type": "testscript",
        "framework": "pytest",
        "swagger_url": "http://mock.com",
        "prompt_text": "Generate testscript"
    }

    response = client.post("/api/testscript-generation", json=request_body)

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "success"
    assert data["execution_status"] == "success"
    assert "generated_code" in data
    assert data["error_message"] == ""


# -------------------------------------------------------------
# TEST 2: Missing mandatory field (input_type)
# -------------------------------------------------------------
def test_missing_input_type():

    request_body = {
        "request_id": "REQ-202",
        "userName": "Tester1",
        # input_type missing intentionally!
        "framework": "pytest",
        "swagger_url": "http://mock.com",
        "prompt_text": "Generate script"
    }

    response = client.post("/api/testscript-generation", json=request_body)

    assert response.status_code == 400
    assert "input type not provided" in response.text.lower()


# -------------------------------------------------------------
# TEST 3: Controller throws exception (tests except block)
# -------------------------------------------------------------
@patch("app.service_generation_service.Controller")
def test_controller_exception(mock_controller):

    # Mock run() to throw exception
    mock_controller.return_value.run.side_effect = Exception("Controller crash!")

    request_body = {
        "request_id": "REQ-303",
        "userName": "TesterA",
        "input_type": "testscript",
        "framework": "pytest",
        "swagger_url": "http://mock.com",
        "prompt_text": "Generate"
    }

    response = client.post("/api/testscript-generation", json=request_body)

    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "failed"
    assert "controller crash" in data["error_message"].lower()
    assert data["generated_code"] == ""


# -------------------------------------------------------------
# TEST 4: DB insertion fails (tests finally block)
# -------------------------------------------------------------
@patch("app.service_generation_service.DataAccessTool")
@patch("app.service_generation_service.Controller")
def test_db_insert_failure(mock_controller, mock_data_access):

    # Mock normal successful run
    mock_controller.return_value.run.return_value = {
        "generated_code": "code",
        "error_message": "",
        "execution_status": "success"
    }

    # Simulate DB insertion failure
    mock_data_access.return_value.db_operation.return_value = False

    request_body = {
        "request_id": "REQ-404",
        "userName": "TesterX",
        "input_type": "testscript",
        "framework": "pytest",
        "swagger_url": "http://mock.com",
        "prompt_text": "Generate"
    }

    response = client.post("/api/testscript-generation", json=request_body)

    assert response.status_code == 200  # API should still return 200
    data = response.json()

    assert data["status"] == "success"  # business status remains success
    assert data["execution_status"] == "success"


# -------------------------------------------------------------
# TEST 5: Invalid graph registry (wrong input_type)
# -------------------------------------------------------------
def test_invalid_graph_registry():

    request_body = {
        "request_id": "REQ-505",
        "userName": "TesterZ",
        "input_type": "wrong_type",
        "framework": "pytest",
        "swagger_url": "http://mock.com",
        "prompt_text": "Gen"
    }

    response = client.post("/api/testscript-generation", json=request_body)

    assert response.status_code == 400
    assert "graph registry" in response.text.lower()
