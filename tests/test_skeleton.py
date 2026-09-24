def test_skeleton_imports():
    from gate.api import create_app
    from gate.service import AdmissionService

    assert create_app is not None
