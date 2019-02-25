"""Acceptance tests for the API.

This assumes that the API server has been started before the test are
run.

"""

def test_auth():
    """It returns the JWT in the 'token' field with the GET /auth/google
    endpoint.

    """
    pass

def test_get_all_cubs():
    """It returns all the cubs in the database with the GET /v1/cubs
    endpoint.

    """
    pass

def test_get_cub_by_name():
    """It returns the cub with name NAME with the GET /v1/cubs?name=<name>
    endpoint.

    """
    pass

def test_create_cub():
    """It creates a cub with the POST /v1/cubs endpoint."""
    pass

def test_get_cub_by_id():
    """It returns the cub with ID with the GET /v1/cubs/<id> endpoint."""
    pass

def test_delete_cub_by_id():
    """It deletes the cub with ID with the DELETE /v1/cubs/<id>
    endpoint.

    """
    pass

def test_patch_cub_by_id():
    """It updtes the cub with ID with the specified fields with the PATCH
    /v1/cubs/<id> endpoint.

    """
    pass
