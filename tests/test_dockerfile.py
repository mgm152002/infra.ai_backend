# ---------------------------------------------------------------------------
# Auto-generated tests for Dockerfile (focus on PR diff contents).
# Test framework: pytest (plain assert style; no new dependencies introduced).
# ---------------------------------------------------------------------------

from pathlib import Path
import os
import re
import pytest
import logging

logger = logging.getLogger(__name__)


def _iter_candidate_dockerfiles():
    """
    Yield candidate Dockerfile paths in the repo, skipping common junk dirs.
    """
    ignore = {".git", "node_modules", "dist", "build", "__pycache__", ".venv", "venv", ".tox"}
    for root, dirs, files in os.walk(".", topdown=True):
        dirs[:] = [d for d in dirs if d not in ignore]
        for name in files:
            if name == "Dockerfile" or name.lower().endswith(".dockerfile"):
                yield Path(root) / name


def _get_target_dockerfile_path():
    """
    Resolve Dockerfile to test:
    - Prefer DOCKERFILE_PATH if set.
    - Else find the first Dockerfile containing the expected Lambda base image.
    - Else fallback to ./Dockerfile if present.
    """
    env = os.getenv("DOCKERFILE_PATH")
    if env and Path(env).is_file():
        return Path(env)

    base_re = re.compile(
        r"^\s*FROM\s+public\.ecr\.aws/lambda/python:3\.11\b",
        re.IGNORECASE | re.MULTILINE,
    )
    for p in _iter_candidate_dockerfiles():
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError as e:
            logger.warning(f"Skipping file {p}: {e}")
            continue
        if base_re.search(text):
            return p

    root_df = Path("Dockerfile")
    return root_df if root_df.is_file() else None


@pytest.fixture(scope="module")
def dockerfile_text():
    """
    Load Dockerfile content once for this test module.
    """
    path = _get_target_dockerfile_path()
    if not path:
        pytest.skip(
            "No Dockerfile with AWS Lambda Python 3.11 base image found. "
            "Set DOCKERFILE_PATH to override."
        )
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        pytest.fail(f"Failed to read Dockerfile at {path}: {e}")


def test_dockerfile_base_image_is_python_3_11(dockerfile_text):
    assert re.search(
        r"^\s*FROM\s+public\.ecr\.aws/lambda/python:3\.11\b",
        dockerfile_text,
        re.IGNORECASE | re.MULTILINE,
    ), (  # noqa: B101
        "Expected base image 'public.ecr.aws/lambda/python:3.11'."
    )


def test_dockerfile_installs_ansible_boto3_awscli_with_no_cache_dir(dockerfile_text):
    m = re.search(
        r"^\s*RUN\s+pip\s+install(?P<rest>.*)$",
        dockerfile_text,
        re.IGNORECASE | re.MULTILINE,
    )
    assert m, "Expected a 'RUN pip install ...' instruction."  # noqa: B101
    rest = m.group("rest")
    assert "--no-cache-dir" in rest, "Expected '--no-cache-dir' in pip install to reduce image size."  # noqa: B101
    for pkg in ("ansible", "boto3", "awscli"):
        assert re.search(rf"\b{pkg}\b", rest, re.IGNORECASE), f"Expected '{pkg}' to be installed by pip."  # noqa: B101


def test_dockerfile_copies_handler_to_lambda_task_root(dockerfile_text):
    assert re.search(
        r"^\s*COPY\s+handler\.py\s+\$\{LAMBDA_TASK_ROOT\}/handler\.py\s*$",
        dockerfile_text,
        re.MULTILINE,
    ), (  # noqa: B101
        "Expected 'COPY handler.py ${LAMBDA_TASK_ROOT}/handler.py'."
    )


def test_dockerfile_cmd_points_to_lambda_handler_json(dockerfile_text):
    assert re.search(
        r'^\s*CMD\s*\[\s*["\']handler\.lambda_handler["\']\s*\]\s*$',
        dockerfile_text,
        re.MULTILINE,
    ), (  # noqa: B101
        'Expected JSON-form CMD: CMD ["handler.lambda_handler"]'
    )


def test_dockerfile_instructions_ordering(dockerfile_text):
    base_m = re.search(
        r"^\s*FROM\s+public\.ecr\.aws/lambda/python:3\.11\b",
        dockerfile_text,
        re.IGNORECASE | re.MULTILINE,
    )
    run_m = re.search(
        r"^\s*RUN\s+pip\s+install\b",
        dockerfile_text,
        re.IGNORECASE | re.MULTILINE,
    )
    copy_m = re.search(
        r"^\s*COPY\s+handler\.py\s+\$\{LAMBDA_TASK_ROOT\}/handler\.py\s*$",
        dockerfile_text,
        re.MULTILINE,
    )
    cmd_m = re.search(r"^\s*CMD\s*\[", dockerfile_text, re.MULTILINE)
    assert base_m and run_m and copy_m and cmd_m, "Missing one or more required Dockerfile instructions."  # noqa: B101
    assert base_m.start() < run_m.start() < copy_m.start() < cmd_m.start(), (  # noqa: B101
        "Expected order: FROM -> RUN pip install -> COPY handler -> CMD."
    )


def test_dockerfile_no_add_for_handler(dockerfile_text):
    assert not re.search(
        r"^\s*ADD\s+handler\.py\b",
        dockerfile_text,
        re.MULTILINE,
    ), (  # noqa: B101
        "Do not use ADD for handler.py; use COPY."
    )


def test_dockerfile_exactly_one_cmd(dockerfile_text):
    cmds = re.findall(r"^\s*CMD\b", dockerfile_text, re.MULTILINE)
    assert len(cmds) == 1, f"Expected exactly one CMD instruction, found {len(cmds)}."  # noqa: B101


def test_dockerfile_no_apt_get_usage(dockerfile_text):
    assert "apt-get" not in dockerfile_text, "Unexpected apt-get usage for AWS Lambda base image."  # noqa: B101