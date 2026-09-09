"""Tests for common module utility functions."""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from common.common import (
    make_output_filename,
    add_common_args,
    is_region_unsupported_error,
)


def test_make_output_filename():
    filename = make_output_filename("ec2", "123456789012", "20260906-120000")
    assert filename == "ec2-inventory-123456789012-20260906-120000.json"


def test_add_common_args():
    parser = argparse.ArgumentParser()
    add_common_args(parser)
    args = parser.parse_args(["-a", "Production", "-r", "us-east-1", "-o", "/tmp/out"])
    assert args.account == "Production"
    assert args.region == "us-east-1"
    assert args.output_dir == "/tmp/out"


def test_is_region_unsupported_error():
    assert is_region_unsupported_error(Exception("OptInRequired: Region not enabled")) is True
    assert is_region_unsupported_error(Exception("EndpointConnectionError: Could not connect")) is True
    assert is_region_unsupported_error(Exception("GenericUnknownError")) is False
