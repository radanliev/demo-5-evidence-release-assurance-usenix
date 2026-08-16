import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from assurance.verifier import evaluate_release_gate

def test_release_gate_approval():
    policy_path = Path(__file__).parent.parent / "governance" / "release_policy.yaml"
    res = evaluate_release_gate(policy_path)
    
    assert res["passed"] is True
    assert res["signed"] is True
    assert res["status"] == "APPROVED"


def test_persistent_nonce_store(tmp_path=None):
    import tempfile
    from assurance.policy import PersistentNonceStore
    
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_file = Path(f.name)
    
    try:
        store1 = PersistentNonceStore(tmp_file)
        assert len(store1) == 0
        store1.add("nonce-123")
        assert "nonce-123" in store1
        assert len(store1) == 1
        
        # Load in a fresh instance to verify persistence across ephemeral processes
        store2 = PersistentNonceStore(tmp_file)
        assert "nonce-123" in store2
        assert len(store2) == 1
        
        store2.discard("nonce-123")
        assert "nonce-123" not in store2
        
        store3 = PersistentNonceStore(tmp_file)
        assert "nonce-123" not in store3
    finally:
        if tmp_file.exists():
            tmp_file.unlink()

