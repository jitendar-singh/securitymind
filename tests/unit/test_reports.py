import os
from pathlib import Path
from unittest.mock import patch

import pytest

from secmind.reports import user_reports_dir


class TestUserReportsDir:
    @patch("secmind.reports._BASE")
    @patch("secmind.reports.current_user_id")
    def test_with_user_context(self, mock_uid, mock_base, tmp_path):
        mock_uid.return_value = 42
        mock_base.__str__ = lambda self: str(tmp_path / "reports")
        base = str(tmp_path / "reports")

        with patch("secmind.reports._BASE", base):
            result = user_reports_dir()
            assert result.endswith("user_42")
            assert os.path.isdir(result)

    @patch("secmind.reports.current_user_id")
    def test_without_user_context(self, mock_uid, tmp_path):
        mock_uid.return_value = None
        base = str(tmp_path / "reports")

        with patch("secmind.reports._BASE", base):
            result = user_reports_dir()
            assert result == base
            assert os.path.isdir(result)

    @patch("secmind.reports.current_user_id")
    def test_creates_directory(self, mock_uid, tmp_path):
        mock_uid.return_value = 7
        base = str(tmp_path / "reports")

        with patch("secmind.reports._BASE", base):
            result = user_reports_dir()
            assert os.path.isdir(result)
            assert "user_7" in result
