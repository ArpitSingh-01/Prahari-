"""Shared pytest options. `--supabase` opts in to the live integration
suite in tests/test_supabase.py (also needs SUPABASE_* env vars)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(os.path.join(HERE, "..")))


def pytest_addoption(parser):
    parser.addoption("--supabase", action="store_true", default=False,
                     help="run live Supabase integration tests")
