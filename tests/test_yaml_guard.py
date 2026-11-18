from security.yaml_guard import (
    is_safe_loader,
    has_python_tag,
    has_duplicate_keys,
    depth_ok,
    alias_count,
    sanitize_comment,
    is_single_document
)


def test_loader():
    assert is_safe_loader('SafeLoader') is True

def test_unsafe_loader():
    assert is_safe_loader('Loader') is False

def test_tag():
    assert has_python_tag('!!python/object/apply:os.system') is True

def test_no_tag():
    assert has_python_tag('a: 1') is False

def test_dup():
    assert has_duplicate_keys('a: 1\na: 2') is True

def test_no_dup():
    assert has_duplicate_keys('a: 1\nb: 2') is False

def test_depth():
    assert depth_ok(3, 5) is True

def test_depth_bad():
    assert depth_ok(6, 5) is False

def test_alias():
    assert alias_count('&a x\n*b') >= 1

def test_comment():
    assert 'secret' not in sanitize_comment('a: 1 # secret')

def test_single():
    assert is_single_document('---\na: 1\n---\nb: 2') is False

def test_single_ok():
    assert is_single_document('a: 1') is True

def test_empty():
    assert is_safe_loader('') is False

def test_merge():
    assert has_duplicate_keys('a: 1\n<<: {a: 2}') is True

def test_safe():
    assert has_python_tag('a: !!str 1') is False
